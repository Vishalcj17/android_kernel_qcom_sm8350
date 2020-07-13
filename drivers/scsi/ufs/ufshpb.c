// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Universal Flash Storage Host Performance Booster
 *
 * Copyright (C) 2017-2018 Samsung Electronics Co., Ltd.
 *
 * Authors:
 *	Yongmyung Lee <ymhungry.lee@samsung.com>
 *	Jinyoung Choi <j-young.choi@samsung.com>
 */

#include <asm/unaligned.h>

#include "ufshcd.h"
#include "ufshpb.h"

static struct ufshpb_driver ufshpb_drv;
unsigned int ufshpb_host_map_kbytes = 1 * 1024;

static int ufshpb_create_sysfs(struct ufs_hba *hba, struct ufshpb_lu *hpb);

static inline int ufshpb_is_valid_srgn(struct ufshpb_region *rgn,
			     struct ufshpb_subregion *srgn)
{
	return rgn->rgn_state != HPB_RGN_INACTIVE &&
		srgn->srgn_state == HPB_SRGN_VALID;
}

static inline bool ufshpb_is_general_lun(int lun)
{
	return lun < UFS_UPIU_MAX_UNIT_NUM_ID;
}

static inline bool
ufshpb_is_pinned_region(struct ufshpb_lu *hpb, int rgn_idx)
{
	if (hpb->lu_pinned_end != PINNED_NOT_SET &&
	    rgn_idx >= hpb->lu_pinned_start &&
	    rgn_idx <= hpb->lu_pinned_end)
		return true;

	return false;
}

static bool ufshpb_is_empty_rsp_lists(struct ufshpb_lu *hpb)
{
	bool ret = true;
	unsigned long flags;

	spin_lock_irqsave(&hpb->rsp_list_lock, flags);
	if (!list_empty(&hpb->lh_inact_rgn) || !list_empty(&hpb->lh_act_srgn))
		ret = false;
	spin_unlock_irqrestore(&hpb->rsp_list_lock, flags);

	return ret;
}

static inline int ufshpb_may_field_valid(struct ufs_hba *hba,
					 struct ufshcd_lrb *lrbp,
					 struct ufshpb_rsp_field *rsp_field)
{
	if (be16_to_cpu(rsp_field->sense_data_len) != DEV_SENSE_SEG_LEN ||
	    rsp_field->desc_type != DEV_DES_TYPE ||
	    rsp_field->additional_len != DEV_ADDITIONAL_LEN ||
	    rsp_field->hpb_type == HPB_RSP_NONE ||
	    rsp_field->active_rgn_cnt > MAX_ACTIVE_NUM ||
	    rsp_field->inactive_rgn_cnt > MAX_INACTIVE_NUM ||
	    (!rsp_field->active_rgn_cnt && !rsp_field->inactive_rgn_cnt))
		return -EINVAL;

	if (!ufshpb_is_general_lun(lrbp->lun)) {
		dev_warn(hba->dev, "ufshpb: lun(%d) not supported\n",
			 lrbp->lun);
		return -EINVAL;
	}

	return 0;
}


static inline struct ufshpb_lu *ufshpb_get_hpb_data(struct scsi_cmnd *cmd)
{
	return cmd->device->hostdata;
}

static inline int ufshpb_get_state(struct ufshpb_lu *hpb)
{
	return atomic_read(&hpb->hpb_state);
}

static inline void ufshpb_set_state(struct ufshpb_lu *hpb, int state)
{
	atomic_set(&hpb->hpb_state, state);
}

static inline int ufshpb_lu_get_dev(struct ufshpb_lu *hpb)
{
	if (get_device(&hpb->hpb_lu_dev))
		return 0;

	return -ENODEV;
}

static inline int ufshpb_lu_get(struct ufshpb_lu *hpb)
{
	if (!hpb || (ufshpb_get_state(hpb) != HPB_PRESENT))
		return -ENODEV;

	if (ufshpb_lu_get_dev(hpb))
		return -ENODEV;

	return 0;
}

static inline void ufshpb_lu_put(struct ufshpb_lu *hpb)
{
	put_device(&hpb->hpb_lu_dev);
}

static struct ufshpb_req *ufshpb_get_map_req(struct ufshpb_lu *hpb,
					     struct ufshpb_subregion *srgn)
{
	struct ufshpb_req *map_req;
	struct request *req;
	struct bio *bio;

	map_req = kmem_cache_alloc(hpb->map_req_cache, GFP_KERNEL);
	if (!map_req)
		return NULL;

	req = blk_get_request(hpb->sdev_ufs_lu->request_queue,
			      REQ_OP_SCSI_IN, BLK_MQ_REQ_PREEMPT);
	if (IS_ERR(req))
		goto free_map_req;

	bio = bio_alloc(GFP_KERNEL, hpb->pages_per_srgn);
	if (!bio) {
		blk_put_request(req);
		goto free_map_req;
	}

	map_req->hpb = hpb;
	map_req->req = req;
	map_req->bio = bio;

	map_req->rgn_idx = srgn->rgn_idx;
	map_req->srgn_idx = srgn->srgn_idx;
	map_req->mctx = srgn->mctx;
	map_req->lun = hpb->lun;

	return map_req;

free_map_req:
	kmem_cache_free(hpb->map_req_cache, map_req);
	return NULL;
}

static inline void ufshpb_put_map_req(struct ufshpb_lu *hpb,
				      struct ufshpb_req *map_req)
{
	bio_put(map_req->bio);
	blk_put_request(map_req->req);
	kmem_cache_free(hpb->map_req_cache, map_req);
}


static inline int ufshpb_clear_dirty_bitmap(struct ufshpb_lu *hpb,
				     struct ufshpb_subregion *srgn)
{
	WARN_ON(!srgn->mctx);
	bitmap_zero(srgn->mctx->ppn_dirty, hpb->entries_per_srgn);
	return 0;
}

static void ufshpb_update_active_info(struct ufshpb_lu *hpb, int rgn_idx,
				      int srgn_idx)
{
	struct ufshpb_region *rgn;
	struct ufshpb_subregion *srgn;

	rgn = hpb->rgn_tbl + rgn_idx;
	srgn = rgn->srgn_tbl + srgn_idx;

	list_del_init(&rgn->list_inact_rgn);

	if (list_empty(&srgn->list_act_srgn))
		list_add_tail(&srgn->list_act_srgn, &hpb->lh_act_srgn);
}

static void ufshpb_update_inactive_info(struct ufshpb_lu *hpb, int rgn_idx)
{
	struct ufshpb_region *rgn;
	struct ufshpb_subregion *srgn;
	int srgn_idx;

	rgn = hpb->rgn_tbl + rgn_idx;

	for (srgn_idx = 0; srgn_idx < rgn->srgn_cnt; srgn_idx++) {
		srgn = rgn->srgn_tbl + srgn_idx;

		list_del_init(&srgn->list_act_srgn);
	}

	if (list_empty(&rgn->list_inact_rgn))
		list_add_tail(&rgn->list_inact_rgn, &hpb->lh_inact_rgn);
}

static void ufshpb_activate_subregion(struct ufshpb_lu *hpb,
					  struct ufshpb_subregion *srgn)
{
	struct ufshpb_region *rgn;

	/*
	 * If there is no mctx in subregion
	 * after I/O progress for HPB_READ_BUFFER, the region to which the
	 * subregion belongs was evicted.
	 * Mask sure the the region must not evict in I/O progress
	 */
	WARN_ON(!srgn->mctx);

	rgn = hpb->rgn_tbl + srgn->rgn_idx;

	if (unlikely(rgn->rgn_state == HPB_RGN_INACTIVE)) {
		dev_err(&hpb->hpb_lu_dev,
			"region %d subregion %d evicted\n",
			srgn->rgn_idx, srgn->srgn_idx);
		return;
	}
	srgn->srgn_state = HPB_SRGN_VALID;
}

static void ufshpb_map_req_compl_fn(struct request *req, blk_status_t error)
{
	struct ufshpb_req *map_req = (struct ufshpb_req *) req->end_io_data;
	struct ufshpb_lu *hpb = map_req->hpb;
	struct ufshpb_subregion *srgn;
	unsigned long flags;

	srgn = hpb->rgn_tbl[map_req->rgn_idx].srgn_tbl +
		map_req->srgn_idx;

	spin_lock_irqsave(&hpb->hpb_state_lock, flags);
	ufshpb_activate_subregion(hpb, srgn);
	spin_unlock_irqrestore(&hpb->hpb_state_lock, flags);

	ufshpb_put_map_req(map_req->hpb, map_req);
	ufshpb_lu_put(hpb);
}

static inline void ufshpb_set_read_buf_cmd(unsigned char *cdb, int rgn_idx,
					   int srgn_idx, int srgn_mem_size)
{
	cdb[0] = UFSHPB_READ_BUFFER;
	cdb[1] = UFSHPB_READ_BUFFER_ID;

	put_unaligned_be16(rgn_idx, &cdb[2]);
	put_unaligned_be16(srgn_idx, &cdb[4]);
	put_unaligned_be24(srgn_mem_size, &cdb[6]);

	cdb[9] = 0x00;
}

static int ufshpb_map_req_add_bio_page(struct ufshpb_lu *hpb,
				       struct request_queue *q, struct bio *bio,
				       struct ufshpb_map_ctx *mctx)
{
	int i, ret = 0;

	for (i = 0; i < hpb->pages_per_srgn; i++) {
		ret = bio_add_pc_page(q, bio, mctx->m_page[i], PAGE_SIZE, 0);
		if (ret != PAGE_SIZE) {
			dev_notice(&hpb->hpb_lu_dev,
				   "bio_add_pc_page fail %d\n", ret);
			return -ENOMEM;
		}
	}

	return 0;
}

static int ufshpb_execute_map_req(struct ufshpb_lu *hpb,
				  struct ufshpb_req *map_req)
{
	struct request_queue *q;
	struct request *req;
	struct scsi_request *rq;
	int ret = 0;

	q = hpb->sdev_ufs_lu->request_queue;
	ret = ufshpb_map_req_add_bio_page(hpb, q, map_req->bio,
					  map_req->mctx);
	if (ret) {
		dev_notice(&hpb->hpb_lu_dev,
			   "map_req_add_bio_page fail %d - %d\n",
			   map_req->rgn_idx, map_req->srgn_idx);
		return ret;
	}

	req = map_req->req;

	blk_rq_append_bio(req, &map_req->bio);

	req->timeout = 0;
	req->end_io_data = (void *)map_req;

	rq = scsi_req(req);
	ufshpb_set_read_buf_cmd(rq->cmd, map_req->rgn_idx,
				map_req->srgn_idx, hpb->srgn_mem_size);
	rq->cmd_len = HPB_READ_BUFFER_CMD_LENGTH;

	blk_execute_rq_nowait(q, NULL, req, 1, ufshpb_map_req_compl_fn);

	atomic_inc(&hpb->stats.map_req_cnt);
	return 0;
}

static struct ufshpb_map_ctx *ufshpb_get_map_ctx(struct ufshpb_lu *hpb)
{
	struct ufshpb_map_ctx *mctx;
	int i, j;

	mctx = mempool_alloc(ufshpb_drv.ufshpb_mctx_pool, GFP_KERNEL);
	if (!mctx)
		return NULL;

	mctx->m_page = kmem_cache_alloc(hpb->m_page_cache, GFP_KERNEL);
	if (!mctx->m_page)
		goto release_mctx;

	mctx->ppn_dirty = bitmap_zalloc(hpb->entries_per_srgn, GFP_KERNEL);
	if (!mctx->ppn_dirty)
		goto release_m_page;

	for (i = 0; i < hpb->pages_per_srgn; i++) {
		mctx->m_page[i] = mempool_alloc(ufshpb_drv.ufshpb_page_pool,
						GFP_KERNEL);
		if (!mctx->m_page[i]) {
			for (j = 0; j < i; j++)
				mempool_free(mctx->m_page[j],
					     ufshpb_drv.ufshpb_page_pool);
			goto release_ppn_dirty;
		}
		clear_page(page_address(mctx->m_page[i]));
	}

	return mctx;
release_ppn_dirty:
	bitmap_free(mctx->ppn_dirty);
release_m_page:
	kmem_cache_free(hpb->m_page_cache, mctx->m_page);
release_mctx:
	mempool_free(mctx, ufshpb_drv.ufshpb_mctx_pool);
	return NULL;
}

static inline void ufshpb_put_map_ctx(struct ufshpb_lu *hpb,
				      struct ufshpb_map_ctx *mctx)
{
	int i;

	for (i = 0; i < hpb->pages_per_srgn; i++)
		mempool_free(mctx->m_page[i],
			     ufshpb_drv.ufshpb_page_pool);

	bitmap_free(mctx->ppn_dirty);
	kmem_cache_free(hpb->m_page_cache, mctx->m_page);
	mempool_free(mctx, ufshpb_drv.ufshpb_mctx_pool);
}

static int ufshpb_check_issue_state_srgns(struct ufshpb_lu *hpb,
					  struct ufshpb_region *rgn)
{
	struct ufshpb_subregion *srgn;
	int srgn_idx;

	for (srgn_idx = 0; srgn_idx < rgn->srgn_cnt; srgn_idx++) {
		srgn  = rgn->srgn_tbl + srgn_idx;

		if (srgn->srgn_state == HPB_SRGN_ISSUED)
			return -EPERM;
	}
	return 0;
}

static inline void ufshpb_add_lru_info(struct victim_select_info *lru_info,
				       struct ufshpb_region *rgn)
{
	rgn->rgn_state = HPB_RGN_ACTIVE;
	list_add_tail(&rgn->list_lru_rgn, &lru_info->lh_lru_rgn);
	atomic_inc(&lru_info->active_cnt);
}

static inline void ufshpb_hit_lru_info(struct victim_select_info *lru_info,
				       struct ufshpb_region *rgn)
{
	list_move_tail(&rgn->list_lru_rgn, &lru_info->lh_lru_rgn);
}

static struct ufshpb_region *ufshpb_victim_lru_info(struct ufshpb_lu *hpb)
{
	struct victim_select_info *lru_info = &hpb->lru_info;
	struct ufshpb_region *rgn, *victim_rgn = NULL;

	list_for_each_entry(rgn, &lru_info->lh_lru_rgn, list_lru_rgn) {
		WARN_ON(!rgn);
		if (ufshpb_check_issue_state_srgns(hpb, rgn))
			continue;

		victim_rgn = rgn;
		break;
	}

	return victim_rgn;
}

static inline void ufshpb_cleanup_lru_info(struct victim_select_info *lru_info,
					   struct ufshpb_region *rgn)
{
	list_del_init(&rgn->list_lru_rgn);
	rgn->rgn_state = HPB_RGN_INACTIVE;
	atomic_dec(&lru_info->active_cnt);
}

static inline void ufshpb_purge_active_subregion(struct ufshpb_lu *hpb,
						 struct ufshpb_subregion *srgn)
{
	if (srgn->srgn_state != HPB_SRGN_UNUSED) {
		ufshpb_put_map_ctx(hpb, srgn->mctx);
		srgn->srgn_state = HPB_SRGN_UNUSED;
		srgn->mctx = NULL;
	}
}

static void __ufshpb_evict_region(struct ufshpb_lu *hpb,
				  struct ufshpb_region *rgn)
{
	struct victim_select_info *lru_info;
	struct ufshpb_subregion *srgn;
	int srgn_idx;

	lru_info = &hpb->lru_info;

	dev_dbg(&hpb->hpb_lu_dev, "evict region %d\n", rgn->rgn_idx);

	ufshpb_cleanup_lru_info(lru_info, rgn);

	for (srgn_idx = 0; srgn_idx < rgn->srgn_cnt; srgn_idx++) {
		srgn = rgn->srgn_tbl + srgn_idx;

		ufshpb_purge_active_subregion(hpb, srgn);
	}
}

static int ufshpb_evict_region(struct ufshpb_lu *hpb, struct ufshpb_region *rgn)
{
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&hpb->hpb_state_lock, flags);
	if (rgn->rgn_state == HPB_RGN_PINNED) {
		dev_warn(&hpb->hpb_lu_dev,
			 "pinned region cannot drop-out. region %d\n",
			 rgn->rgn_idx);
		goto out;
	}
	if (!list_empty(&rgn->list_lru_rgn)) {
		if (ufshpb_check_issue_state_srgns(hpb, rgn)) {
			ret = -EBUSY;
			goto out;
		}

		__ufshpb_evict_region(hpb, rgn);
	}
out:
	spin_unlock_irqrestore(&hpb->hpb_state_lock, flags);
	return ret;
}

static inline struct
ufshpb_rsp_field *ufshpb_get_hpb_rsp(struct ufshcd_lrb *lrbp)
{
	return (struct ufshpb_rsp_field *)&lrbp->ucd_rsp_ptr->sr.sense_data_len;
}

static int ufshpb_issue_map_req(struct ufshpb_lu *hpb,
				struct ufshpb_region *rgn,
				struct ufshpb_subregion *srgn)
{
	struct ufshpb_req *map_req;
	unsigned long flags;
	int ret;
	int err = -EAGAIN;
	bool alloc_required = false;
	enum HPB_RGN_STATE state = HPB_SRGN_INVALID;

	spin_lock_irqsave(&hpb->hpb_state_lock, flags);
	/*
	 * Since the region state change occurs only in the map_work,
	 * the state of the region cannot HPB_RGN_INACTIVE at this point.
	 * The region state must be changed in the map_work
	 */
	WARN_ON(rgn->rgn_state == HPB_RGN_INACTIVE);

	if (srgn->srgn_state == HPB_SRGN_UNUSED)
		alloc_required = true;

	/*
	 * If the subregion is already ISSUED state,
	 * a specific event (e.g., GC or wear-leveling, etc.) occurs in
	 * the device and HPB response for map loading is received.
	 * In this case, after finishing the HPB_READ_BUFFER,
	 * the next HPB_READ_BUFFER is performed again to obtain the latest
	 * map data.
	 */
	if (srgn->srgn_state == HPB_SRGN_ISSUED)
		goto unlock_out;

	srgn->srgn_state = HPB_SRGN_ISSUED;
	spin_unlock_irqrestore(&hpb->hpb_state_lock, flags);

	if (alloc_required) {
		WARN_ON(srgn->mctx);
		srgn->mctx = ufshpb_get_map_ctx(hpb);
		if (!srgn->mctx) {
			dev_notice(&hpb->hpb_lu_dev,
			    "get map_ctx failed. region %d - %d\n",
			    rgn->rgn_idx, srgn->srgn_idx);
			state = HPB_SRGN_UNUSED;
			goto change_srgn_state;
		}
	}

	ufshpb_clear_dirty_bitmap(hpb, srgn);
	map_req = ufshpb_get_map_req(hpb, srgn);
	if (!map_req)
		goto change_srgn_state;

	ret = ufshpb_lu_get(hpb);
	if (unlikely(ret)) {
		dev_notice(&hpb->hpb_lu_dev,
			   "%s: ufshpb_lu_get failed: %d", __func__, ret);
		goto free_map_req;
	}

	ret = ufshpb_execute_map_req(hpb, map_req);
	if (ret) {
		dev_notice(&hpb->hpb_lu_dev,
			   "%s: issue map_req failed: %d, region %d - %d\n",
			   __func__, ret, srgn->rgn_idx, srgn->srgn_idx);
		ufshpb_lu_put(hpb);
		goto free_map_req;
	}
	return 0;

free_map_req:
	ufshpb_put_map_req(hpb, map_req);
change_srgn_state:
	spin_lock_irqsave(&hpb->hpb_state_lock, flags);
	srgn->srgn_state = state;
unlock_out:
	spin_unlock_irqrestore(&hpb->hpb_state_lock, flags);
	return err;
}

static int ufshpb_add_region(struct ufshpb_lu *hpb, struct ufshpb_region *rgn)
{
	struct ufshpb_region *victim_rgn;
	struct victim_select_info *lru_info = &hpb->lru_info;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&hpb->hpb_state_lock, flags);
	/*
	 * If region belongs to lru_list, just move the region
	 * to the front of lru list. because the state of the region
	 * is already active-state
	 */
	if (!list_empty(&rgn->list_lru_rgn)) {
		ufshpb_hit_lru_info(lru_info, rgn);
		goto out;
	}

	if (rgn->rgn_state == HPB_RGN_INACTIVE) {
		if (atomic_read(&lru_info->active_cnt)
		    == lru_info->max_lru_active_cnt) {
			/*
			 * If the maximum number of active regions
			 * is exceeded, evict the least recently used region.
			 * This case may occur when the device responds
			 * to the eviction information late.
			 * It is okay to evict the least recently used region,
			 * because the device could detect this region
			 * by not issuing HPB_READ
			 */
			victim_rgn = ufshpb_victim_lru_info(hpb);
			if (!victim_rgn) {
				dev_warn(&hpb->hpb_lu_dev,
				    "cannot get victim region error\n");
				ret = -ENOMEM;
				goto out;
			}

			dev_dbg(&hpb->hpb_lu_dev,
				"LRU full (%d), choost victim %d\n",
				atomic_read(&lru_info->active_cnt),
				victim_rgn->rgn_idx);
			__ufshpb_evict_region(hpb, victim_rgn);
		}

		/*
		 * When a region is added to lru_info list_head,
		 * it is guaranteed that the subregion has been
		 * assigned all mctx. If failed, try to receive mctx again
		 * without being added to lru_info list_head
		 */
		ufshpb_add_lru_info(lru_info, rgn);
	}
out:
	spin_unlock_irqrestore(&hpb->hpb_state_lock, flags);
	return ret;
}

static void ufshpb_rsp_req_region_update(struct ufshpb_lu *hpb,
					 struct ufshpb_rsp_field *rsp_field)
{
	int i, rgn_idx, srgn_idx;

	/*
	 * If the active region and the inactive region are the same,
	 * we will inactivate this region.
	 * The device could check this (region inactivated) and
	 * will response the proper active region information
	 */
	spin_lock(&hpb->rsp_list_lock);
	for (i = 0; i < rsp_field->active_rgn_cnt; i++) {
		rgn_idx =
			be16_to_cpu(rsp_field->hpb_active_field[i].active_rgn);
		srgn_idx =
			be16_to_cpu(rsp_field->hpb_active_field[i].active_srgn);

		dev_dbg(&hpb->hpb_lu_dev, "activate(%d) region %d - %d\n",
			i, rgn_idx, srgn_idx);
		ufshpb_update_active_info(hpb, rgn_idx, srgn_idx);
		atomic_inc(&hpb->stats.rb_active_cnt);
	}

	for (i = 0; i < rsp_field->inactive_rgn_cnt; i++) {
		rgn_idx = be16_to_cpu(rsp_field->hpb_inactive_field[i]);
		dev_dbg(&hpb->hpb_lu_dev, "inactivate(%d) region %d\n",
			i, rgn_idx);
		ufshpb_update_inactive_info(hpb, rgn_idx);
		atomic_inc(&hpb->stats.rb_inactive_cnt);
	}
	spin_unlock(&hpb->rsp_list_lock);

	dev_dbg(&hpb->hpb_lu_dev, "Noti: #ACT %u #INACT %u\n",
		rsp_field->active_rgn_cnt, rsp_field->inactive_rgn_cnt);

	queue_work(ufshpb_drv.ufshpb_wq, &hpb->map_work);
}

/* routine : isr (ufs) */
static void ufshpb_rsp_upiu(struct ufs_hba *hba, struct ufshcd_lrb *lrbp)
{
	struct ufshpb_lu *hpb;
	struct ufshpb_rsp_field *rsp_field;
	int data_seg_len, ret;

	data_seg_len = be32_to_cpu(lrbp->ucd_rsp_ptr->header.dword_2)
		& MASK_RSP_UPIU_DATA_SEG_LEN;

	/* To flush remained rsp_list, we queue the map_work task */
	if (!data_seg_len) {
		if (!ufshpb_is_general_lun(lrbp->lun))
			return;

		hpb = ufshpb_get_hpb_data(lrbp->cmd);
		ret = ufshpb_lu_get(hpb);
		if (ret)
			return;

		if (!ufshpb_is_empty_rsp_lists(hpb))
			queue_work(ufshpb_drv.ufshpb_wq, &hpb->map_work);

		goto put_hpb;
	}

	/* Check HPB_UPDATE_ALERT */
	if (!(lrbp->ucd_rsp_ptr->header.dword_2 &
	      UPIU_HEADER_DWORD(0, 2, 0, 0)))
		return;

	rsp_field = ufshpb_get_hpb_rsp(lrbp);
	if (ufshpb_may_field_valid(hba, lrbp, rsp_field))
		return;

	hpb = ufshpb_get_hpb_data(lrbp->cmd);
	ret = ufshpb_lu_get(hpb);
	if (ret)
		return;

	atomic_inc(&hpb->stats.rb_noti_cnt);

	switch (rsp_field->hpb_type) {
	case HPB_RSP_REQ_REGION_UPDATE:
		WARN_ON(data_seg_len != DEV_DATA_SEG_LEN);
		ufshpb_rsp_req_region_update(hpb, rsp_field);
		break;
	case HPB_RSP_DEV_RESET:
		dev_warn(&hpb->hpb_lu_dev,
			 "UFS device lost HPB information during PM.\n");
		break;
	default:
		dev_notice(&hpb->hpb_lu_dev, "hpb_type is not available: %d\n",
			   rsp_field->hpb_type);
		break;
	}
put_hpb:
	ufshpb_lu_put(hpb);
}

static void ufshpb_add_active_list(struct ufshpb_lu *hpb,
				   struct ufshpb_region *rgn,
				   struct ufshpb_subregion *srgn)
{
	if (!list_empty(&rgn->list_inact_rgn))
		return;

	if (!list_empty(&srgn->list_act_srgn)) {
		list_move(&srgn->list_act_srgn, &hpb->lh_act_srgn);
		return;
	}

	list_add(&srgn->list_act_srgn, &hpb->lh_act_srgn);
}

static void ufshpb_add_pending_evict_list(struct ufshpb_lu *hpb,
				    struct ufshpb_region *rgn,
				    struct list_head *pending_list)
{
	struct ufshpb_subregion *srgn;
	int srgn_idx;

	if (!list_empty(&rgn->list_inact_rgn))
		return;

	for (srgn_idx = 0; srgn_idx < rgn->srgn_cnt; srgn_idx++) {
		srgn = rgn->srgn_tbl + srgn_idx;

		if (!list_empty(&srgn->list_act_srgn))
			return;
	}

	list_add_tail(&rgn->list_inact_rgn, pending_list);
}

static void ufshpb_run_active_subregion_list(struct ufshpb_lu *hpb)
{
	struct ufshpb_region *rgn;
	struct ufshpb_subregion *srgn;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&hpb->rsp_list_lock, flags);
	while ((srgn = list_first_entry_or_null(&hpb->lh_act_srgn,
						struct ufshpb_subregion,
						list_act_srgn))) {
		list_del_init(&srgn->list_act_srgn);
		spin_unlock_irqrestore(&hpb->rsp_list_lock, flags);

		rgn = hpb->rgn_tbl + srgn->rgn_idx;
		ret = ufshpb_add_region(hpb, rgn);
		if (ret)
			break;

		ret = ufshpb_issue_map_req(hpb, rgn, srgn);
		if (ret) {
			dev_notice(&hpb->hpb_lu_dev,
			    "issue map_req failed. ret %d, region %d - %d\n",
			    ret, rgn->rgn_idx, srgn->srgn_idx);
			break;
		}
		spin_lock_irqsave(&hpb->rsp_list_lock, flags);
	}

	if (ret) {
		dev_notice(&hpb->hpb_lu_dev, "region %d - %d, will retry\n",
			   rgn->rgn_idx, srgn->srgn_idx);
		spin_lock_irqsave(&hpb->rsp_list_lock, flags);
		ufshpb_add_active_list(hpb, rgn, srgn);
	}
	spin_unlock_irqrestore(&hpb->rsp_list_lock, flags);
}

static void ufshpb_run_inactive_region_list(struct ufshpb_lu *hpb)
{
	struct ufshpb_region *rgn;
	unsigned long flags;
	int ret;
	LIST_HEAD(pending_list);

	spin_lock_irqsave(&hpb->rsp_list_lock, flags);
	while ((rgn = list_first_entry_or_null(&hpb->lh_inact_rgn,
					       struct ufshpb_region,
					       list_inact_rgn))) {
		list_del_init(&rgn->list_inact_rgn);
		spin_unlock_irqrestore(&hpb->rsp_list_lock, flags);

		ret = ufshpb_evict_region(hpb, rgn);
		if (ret) {
			spin_lock_irqsave(&hpb->rsp_list_lock, flags);
			ufshpb_add_pending_evict_list(hpb, rgn, &pending_list);
			spin_unlock_irqrestore(&hpb->rsp_list_lock, flags);
		}

		spin_lock_irqsave(&hpb->rsp_list_lock, flags);
	}

	list_splice(&pending_list, &hpb->lh_inact_rgn);
	spin_unlock_irqrestore(&hpb->rsp_list_lock, flags);
}

static void ufshpb_map_work_handler(struct work_struct *work)
{
	struct ufshpb_lu *hpb;
	int ret;

	hpb = container_of(work, struct ufshpb_lu, map_work);
	ret = ufshpb_lu_get(hpb);
	if (ret) {
		dev_info(&hpb->hpb_lu_dev, "%s: exit, state %d\n",
			 __func__, ufshpb_get_state(hpb));
		return;
	}

	ufshpb_run_inactive_region_list(hpb);
	ufshpb_run_active_subregion_list(hpb);

	ufshpb_lu_put(hpb);
}

/*
 * this function doesn't need to hold lock due to be called in init.
 * (hpb_state_lock, rsp_list_lock, etc..)
 */
static int ufshpb_init_pinned_active_region(struct ufs_hba *hba,
					    struct ufshpb_lu *hpb,
					    struct ufshpb_region *rgn)
{
	struct ufshpb_subregion *srgn;
	int srgn_idx, i;
	int err = 0;

	for (srgn_idx = 0; srgn_idx < rgn->srgn_cnt; srgn_idx++) {
		srgn = rgn->srgn_tbl + srgn_idx;

		srgn->mctx = ufshpb_get_map_ctx(hpb);
		srgn->srgn_state = HPB_SRGN_INVALID;
		if (!srgn->mctx) {
			dev_err(hba->dev,
				"alloc mctx for pinned region failed\n");
			goto release;
		}

		list_add_tail(&srgn->list_act_srgn, &hpb->lh_act_srgn);
	}

	rgn->rgn_state = HPB_RGN_PINNED;
	return 0;

release:
	for (i = 0; i < srgn_idx; i++) {
		srgn = rgn->srgn_tbl + i;
		ufshpb_put_map_ctx(hpb, srgn->mctx);
	}
	return err;
}

static void ufshpb_init_subregion_tbl(struct ufshpb_lu *hpb,
				      struct ufshpb_region *rgn)
{
	int srgn_idx;

	for (srgn_idx = 0; srgn_idx < rgn->srgn_cnt; srgn_idx++) {
		struct ufshpb_subregion *srgn = rgn->srgn_tbl + srgn_idx;

		INIT_LIST_HEAD(&srgn->list_act_srgn);

		srgn->rgn_idx = rgn->rgn_idx;
		srgn->srgn_idx = srgn_idx;
		srgn->srgn_state = HPB_SRGN_UNUSED;
	}
}

static inline int ufshpb_alloc_subregion_tbl(struct ufshpb_lu *hpb,
					     struct ufshpb_region *rgn,
					     int srgn_cnt)
{
	rgn->srgn_tbl = kvcalloc(srgn_cnt, sizeof(struct ufshpb_subregion),
				 GFP_KERNEL);
	if (!rgn->srgn_tbl)
		return -ENOMEM;

	rgn->srgn_cnt = srgn_cnt;
	return 0;
}

static void ufshpb_init_lu_parameter(struct ufs_hba *hba,
				     struct ufshpb_lu *hpb,
				     struct ufshpb_dev_info *hpb_dev_info,
				     struct ufshpb_lu_info *hpb_lu_info)
{
	u32 entries_per_rgn;
	u64 rgn_mem_size;


	hpb->lu_pinned_start = hpb_lu_info->pinned_start;
	hpb->lu_pinned_end = hpb_lu_info->num_pinned ?
		(hpb_lu_info->pinned_start + hpb_lu_info->num_pinned - 1)
		: PINNED_NOT_SET;
	hpb->lru_info.max_lru_active_cnt =
		hpb_lu_info->max_active_rgns - hpb_lu_info->num_pinned;

	rgn_mem_size = (1ULL << hpb_dev_info->rgn_size) * HPB_RGN_SIZE_UNIT
		/ HPB_ENTRY_BLOCK_SIZE * HPB_ENTRY_SIZE;
	hpb->srgn_mem_size = (1ULL << hpb_dev_info->srgn_size)
		* HPB_RGN_SIZE_UNIT / HPB_ENTRY_BLOCK_SIZE * HPB_ENTRY_SIZE;

	entries_per_rgn = rgn_mem_size / HPB_ENTRY_SIZE;
	hpb->entries_per_rgn_shift = ilog2(entries_per_rgn);
	hpb->entries_per_rgn_mask = entries_per_rgn - 1;

	hpb->entries_per_srgn = hpb->srgn_mem_size /  HPB_ENTRY_SIZE;
	hpb->entries_per_srgn_shift = ilog2(hpb->entries_per_srgn);
	hpb->entries_per_srgn_mask = hpb->entries_per_srgn - 1;

	hpb->srgns_per_rgn = rgn_mem_size / hpb->srgn_mem_size;

	hpb->rgns_per_lu = DIV_ROUND_UP(hpb_lu_info->num_blocks,
				(rgn_mem_size / HPB_ENTRY_SIZE));
	hpb->srgns_per_lu = DIV_ROUND_UP(hpb_lu_info->num_blocks,
				(hpb->srgn_mem_size / HPB_ENTRY_SIZE));

	hpb->pages_per_srgn = hpb->srgn_mem_size / PAGE_SIZE;

	dev_info(hba->dev, "ufshpb(%d): region memory size - %llu (bytes)\n",
		 hpb->lun, rgn_mem_size);
	dev_info(hba->dev, "ufshpb(%d): subregion memory size - %u (bytes)\n",
		 hpb->lun, hpb->srgn_mem_size);
	dev_info(hba->dev, "ufshpb(%d): total blocks per lu - %d\n",
		 hpb->lun, hpb_lu_info->num_blocks);
	dev_info(hba->dev, "ufshpb(%d): subregions per region - %d, regions per lu - %u",
		 hpb->lun, hpb->srgns_per_rgn, hpb->rgns_per_lu);
}


static int ufshpb_alloc_region_tbl(struct ufs_hba *hba, struct ufshpb_lu *hpb)
{
	struct ufshpb_region *rgn_table, *rgn;
	int rgn_idx, i;
	int ret = 0;

	rgn_table = kvcalloc(hpb->rgns_per_lu, sizeof(struct ufshpb_region),
			    GFP_KERNEL);
	if (!rgn_table)
		return -ENOMEM;

	hpb->rgn_tbl = rgn_table;

	for (rgn_idx = 0; rgn_idx < hpb->rgns_per_lu; rgn_idx++) {
		int srgn_cnt = hpb->srgns_per_rgn;

		rgn = rgn_table + rgn_idx;
		rgn->rgn_idx = rgn_idx;

		INIT_LIST_HEAD(&rgn->list_inact_rgn);
		INIT_LIST_HEAD(&rgn->list_lru_rgn);

		if (rgn_idx == hpb->rgns_per_lu - 1)
			srgn_cnt = ((hpb->srgns_per_lu - 1) %
				    hpb->srgns_per_rgn) + 1;

		ret = ufshpb_alloc_subregion_tbl(hpb, rgn, srgn_cnt);
		if (ret)
			goto release_srgn_table;
		ufshpb_init_subregion_tbl(hpb, rgn);

		if (ufshpb_is_pinned_region(hpb, rgn_idx)) {
			ret = ufshpb_init_pinned_active_region(hba, hpb, rgn);
			if (ret)
				goto release_srgn_table;
		} else {
			rgn->rgn_state = HPB_RGN_INACTIVE;
		}
	}

	return 0;

release_srgn_table:
	for (i = 0; i < rgn_idx; i++) {
		rgn = rgn_table + i;
		if (rgn->srgn_tbl)
			kvfree(rgn->srgn_tbl);
	}
	kvfree(rgn_table);
	return ret;
}

static void ufshpb_destroy_subregion_tbl(struct ufshpb_lu *hpb,
					 struct ufshpb_region *rgn)
{
	int srgn_idx;

	for (srgn_idx = 0; srgn_idx < rgn->srgn_cnt; srgn_idx++) {
		struct ufshpb_subregion *srgn;

		srgn = rgn->srgn_tbl + srgn_idx;
		if (srgn->srgn_state != HPB_SRGN_UNUSED) {
			srgn->srgn_state = HPB_SRGN_UNUSED;
			ufshpb_put_map_ctx(hpb, srgn->mctx);
		}
	}
}

static void ufshpb_destroy_region_tbl(struct ufshpb_lu *hpb)
{
	int rgn_idx;

	for (rgn_idx = 0; rgn_idx < hpb->rgns_per_lu; rgn_idx++) {
		struct ufshpb_region *rgn;

		rgn = hpb->rgn_tbl + rgn_idx;
		if (rgn->rgn_state != HPB_RGN_INACTIVE) {
			rgn->rgn_state = HPB_RGN_INACTIVE;

			ufshpb_destroy_subregion_tbl(hpb, rgn);
		}

		kvfree(rgn->srgn_tbl);
	}

	kvfree(hpb->rgn_tbl);
}

static int ufshpb_lu_hpb_init(struct ufs_hba *hba, struct ufshpb_lu *hpb,
			      struct ufshpb_dev_info *hpb_dev_info)
{
	int ret;

	spin_lock_init(&hpb->hpb_state_lock);
	spin_lock_init(&hpb->rsp_list_lock);

	INIT_LIST_HEAD(&hpb->lru_info.lh_lru_rgn);
	INIT_LIST_HEAD(&hpb->lh_act_srgn);
	INIT_LIST_HEAD(&hpb->lh_inact_rgn);
	INIT_LIST_HEAD(&hpb->list_hpb_lu);

	INIT_WORK(&hpb->map_work, ufshpb_map_work_handler);

	hpb->map_req_cache = kmem_cache_create("ufshpb_req_cache",
			  sizeof(struct ufshpb_req), 0, 0, NULL);
	if (!hpb->map_req_cache) {
		dev_err(hba->dev, "ufshpb(%d) ufshpb_req_cache create fail",
			hpb->lun);
		return -ENOMEM;
	}

	hpb->m_page_cache = kmem_cache_create("ufshpb_m_page_cache",
			  sizeof(struct page *) * hpb->pages_per_srgn,
			  0, 0, NULL);
	if (!hpb->m_page_cache) {
		dev_err(hba->dev, "ufshpb(%d) ufshpb_m_page_cache create fail",
			hpb->lun);
		ret = -ENOMEM;
		goto release_req_cache;
	}

	ret = ufshpb_alloc_region_tbl(hba, hpb);
	if (ret)
		goto release_m_page_cache;

	ret = ufshpb_create_sysfs(hba, hpb);
	if (ret)
		goto release_rgn_table;

	return 0;

release_rgn_table:
	ufshpb_destroy_region_tbl(hpb);
release_m_page_cache:
	kmem_cache_destroy(hpb->m_page_cache);
release_req_cache:
	kmem_cache_destroy(hpb->map_req_cache);
	return ret;
}

static struct ufshpb_lu *ufshpb_alloc_hpb_lu(struct ufs_hba *hba, int lun,
				     struct ufshpb_dev_info *hpb_dev_info,
				     struct ufshpb_lu_info *hpb_lu_info)
{
	struct ufshpb_lu *hpb;
	int ret;

	hpb = kzalloc(sizeof(struct ufshpb_lu), GFP_KERNEL);
	if (!hpb)
		return NULL;

	hpb->ufsf = &hba->ufsf;
	hpb->lun = lun;

	ufshpb_init_lu_parameter(hba, hpb, hpb_dev_info, hpb_lu_info);

	ret = ufshpb_lu_hpb_init(hba, hpb, hpb_dev_info);
	if (ret) {
		dev_err(hba->dev, "hpb lu init failed. ret %d", ret);
		goto release_hpb;
	}

	return hpb;
release_hpb:
	kfree(hpb);
	return NULL;
}

static void ufshpb_discard_rsp_lists(struct ufshpb_lu *hpb)
{
	struct ufshpb_region *rgn, *next_rgn;
	struct ufshpb_subregion *srgn, *next_srgn;
	unsigned long flags;

	/*
	 * If the device reset occurred, the remained HPB region information
	 * may be stale. Therefore, by dicarding the lists of HPB response
	 * that remained after reset, it prevents unnecessary work.
	 */
	spin_lock_irqsave(&hpb->rsp_list_lock, flags);
	list_for_each_entry_safe(rgn, next_rgn, &hpb->lh_inact_rgn,
				 list_inact_rgn)
		list_del_init(&rgn->list_inact_rgn);

	list_for_each_entry_safe(srgn, next_srgn, &hpb->lh_act_srgn,
				 list_act_srgn)
		list_del_init(&srgn->list_act_srgn);
	spin_unlock_irqrestore(&hpb->rsp_list_lock, flags);
}

static inline void ufshpb_cancel_jobs(struct ufshpb_lu *hpb)
{
	cancel_work_sync(&hpb->map_work);
}

static void ufshpb_lu_release(struct ufshpb_lu *hpb)
{
	ufshpb_cancel_jobs(hpb);

	ufshpb_destroy_region_tbl(hpb);

	kmem_cache_destroy(hpb->map_req_cache);
	kmem_cache_destroy(hpb->m_page_cache);

	list_del_init(&hpb->list_hpb_lu);
}

static void ufshpb_issue_hpb_reset_query(struct ufs_hba *hba)
{
	int err;
	int retries;

	for (retries = 0; retries < HPB_RESET_REQ_RETRIES; retries++) {
		err = ufshcd_query_flag(hba, UPIU_QUERY_OPCODE_SET_FLAG,
				QUERY_FLAG_IDN_HPB_RESET, 0, NULL);
		if (err)
			dev_dbg(hba->dev,
				"%s: failed with error %d, retries %d\n",
				__func__, err, retries);
		else
			break;
	}

	if (err) {
		dev_err(hba->dev,
			"%s setting fHpbReset flag failed with error %d\n",
			__func__, err);
		return;
	}
}

static void ufshpb_check_hpb_reset_query(struct ufs_hba *hba)
{
	int err;
	bool flag_res = true;
	int try = 0;

	/* wait for the device to complete HPB reset query */
	do {
		if (++try == HPB_RESET_REQ_RETRIES)
			break;

		dev_info(hba->dev,
			"%s start flag reset polling %d times\n",
			__func__, try);

		/* Poll fHpbReset flag to be cleared */
		err = ufshcd_query_flag(hba, UPIU_QUERY_OPCODE_READ_FLAG,
				QUERY_FLAG_IDN_HPB_RESET, 0, &flag_res);
		usleep_range(1000, 1100);
	} while (flag_res);

	if (err) {
		dev_err(hba->dev,
			"%s reading fHpbReset flag failed with error %d\n",
			__func__, err);
		return;
	}

	if (flag_res) {
		dev_err(hba->dev,
			"%s fHpbReset was not cleared by the device\n",
			__func__);
	}
}

static void ufshpb_reset(struct ufs_hba *hba)
{
	struct ufshpb_lu *hpb;

	list_for_each_entry(hpb, &ufshpb_drv.lh_hpb_lu, list_hpb_lu) {
		if (ufshpb_lu_get_dev(hpb))
			continue;

		ufshpb_set_state(hpb, HPB_PRESENT);
		ufshpb_lu_put(hpb);
	}
}

static void ufshpb_reset_host(struct ufs_hba *hba)
{
	struct ufshpb_lu *hpb;

	list_for_each_entry(hpb, &ufshpb_drv.lh_hpb_lu, list_hpb_lu) {
		if (ufshpb_lu_get(hpb))
			continue;

		dev_info(&hpb->hpb_lu_dev, "ufshpb run reset_host");

		ufshpb_set_state(hpb, HPB_RESET);
		ufshpb_cancel_jobs(hpb);
		ufshpb_discard_rsp_lists(hpb);

		ufshpb_lu_put(hpb);
	}
}

static void ufshpb_suspend(struct ufs_hba *hba)
{
	struct ufshpb_lu *hpb;

	list_for_each_entry(hpb, &ufshpb_drv.lh_hpb_lu, list_hpb_lu) {
		if (ufshpb_lu_get(hpb))
			continue;

		dev_info(&hpb->hpb_lu_dev, "ufshpb goto suspend");
		ufshpb_set_state(hpb, HPB_SUSPEND);
		ufshpb_cancel_jobs(hpb);

		ufshpb_lu_put(hpb);
	}
}

static void ufshpb_resume(struct ufs_hba *hba)
{
	struct ufshpb_lu *hpb;

	list_for_each_entry(hpb, &ufshpb_drv.lh_hpb_lu, list_hpb_lu) {
		if (ufshpb_lu_get_dev(hpb))
			continue;

		dev_info(&hpb->hpb_lu_dev, "ufshpb resume");
		ufshpb_set_state(hpb, HPB_PRESENT);
		if (!ufshpb_is_empty_rsp_lists(hpb))
			queue_work(ufshpb_drv.ufshpb_wq, &hpb->map_work);

		ufshpb_lu_put(hpb);
	}
}

static void ufshpb_stat_init(struct ufshpb_lu *hpb)
{
	atomic_set(&hpb->stats.hit_cnt, 0);
	atomic_set(&hpb->stats.miss_cnt, 0);
	atomic_set(&hpb->stats.rb_noti_cnt, 0);
	atomic_set(&hpb->stats.rb_active_cnt, 0);
	atomic_set(&hpb->stats.rb_inactive_cnt, 0);
	atomic_set(&hpb->stats.map_req_cnt, 0);
}

/* SYSFS functions */
#define ufshpb_sysfs_attr_show_func(__name)				\
static ssize_t __name##_show(struct device *dev,		\
					 struct device_attribute *attr,	\
					 char *buf)			\
{									\
	struct ufshpb_lu *hpb;						\
	hpb = container_of(dev, struct ufshpb_lu, hpb_lu_dev);		\
	return snprintf(buf, PAGE_SIZE, "%d\n",			\
			atomic_read(&hpb->stats.__name));		\
}

ufshpb_sysfs_attr_show_func(hit_cnt);
ufshpb_sysfs_attr_show_func(miss_cnt);
ufshpb_sysfs_attr_show_func(rb_noti_cnt);
ufshpb_sysfs_attr_show_func(rb_active_cnt);
ufshpb_sysfs_attr_show_func(rb_inactive_cnt);
ufshpb_sysfs_attr_show_func(map_req_cnt);

static DEVICE_ATTR_RO(hit_cnt);
static DEVICE_ATTR_RO(miss_cnt);
static DEVICE_ATTR_RO(rb_noti_cnt);
static DEVICE_ATTR_RO(rb_active_cnt);
static DEVICE_ATTR_RO(rb_inactive_cnt);
static DEVICE_ATTR_RO(map_req_cnt);

static struct attribute *hpb_dev_attrs[] = {
	&dev_attr_hit_cnt.attr,
	&dev_attr_miss_cnt.attr,
	&dev_attr_rb_noti_cnt.attr,
	&dev_attr_rb_active_cnt.attr,
	&dev_attr_rb_inactive_cnt.attr,
	&dev_attr_map_req_cnt.attr,
	NULL,
};

static struct attribute_group ufshpb_sysfs_group = {
	.attrs = hpb_dev_attrs,
};

static inline void ufshpb_dev_release(struct device *dev)
{
	struct ufs_hba *hba;
	struct ufsf_feature_info *ufsf;
	struct ufshpb_lu *hpb;

	hpb = container_of(dev, struct ufshpb_lu, hpb_lu_dev);
	ufsf = hpb->ufsf;
	hba = container_of(ufsf, struct ufs_hba, ufsf);

	ufshpb_lu_release(hpb);
	dev_info(dev, "%s: release success\n", __func__);
	put_device(dev->parent);

	kfree(hpb);
}

static int ufshpb_create_sysfs(struct ufs_hba *hba, struct ufshpb_lu *hpb)
{
	int ret;

	device_initialize(&hpb->hpb_lu_dev);

	ufshpb_stat_init(hpb);

	hpb->hpb_lu_dev.parent = get_device(&hba->ufsf.hpb_dev);
	hpb->hpb_lu_dev.release = ufshpb_dev_release;
	dev_set_name(&hpb->hpb_lu_dev, "ufshpb_lu%d", hpb->lun);

	ret = device_add(&hpb->hpb_lu_dev);
	if (ret) {
		dev_err(hba->dev, "ufshpb(%d) device_add failed",
			hpb->lun);
		return -ENODEV;
	}

	if (device_add_group(&hpb->hpb_lu_dev, &ufshpb_sysfs_group))
		dev_err(hba->dev, "ufshpb(%d) create file error\n",
			hpb->lun);

	return 0;
}

static int ufshpb_read_desc(struct ufs_hba *hba, u8 desc_id, u8 desc_index,
			  u8 selector, u8 *desc_buf)
{
	int err = 0;
	int size;

	ufshcd_map_desc_id_to_length(hba, desc_id, &size);

	pm_runtime_get_sync(hba->dev);

	err = ufshcd_query_descriptor_retry(hba, UPIU_QUERY_OPCODE_READ_DESC,
					    desc_id, desc_index,
					    selector,
					    desc_buf, &size);
	if (err)
		dev_err(hba->dev, "read desc failed: %d, id %d, idx %d\n",
			err, desc_id, desc_index);

	pm_runtime_put_sync(hba->dev);

	return err;
}

static int ufshpb_get_geo_info(struct ufs_hba *hba, u8 *geo_buf,
			       struct ufshpb_dev_info *hpb_dev_info)
{
	int hpb_device_max_active_rgns = 0;
	int hpb_num_lu;

	hpb_num_lu = geo_buf[GEOMETRY_DESC_HPB_NUMBER_LU];
	if (hpb_num_lu == 0) {
		dev_err(hba->dev, "No HPB LU supported\n");
		return -ENODEV;
	}

	hpb_dev_info->rgn_size = geo_buf[GEOMETRY_DESC_HPB_REGION_SIZE];
	hpb_dev_info->srgn_size = geo_buf[GEOMETRY_DESC_HPB_SUBREGION_SIZE];
	hpb_device_max_active_rgns =
		get_unaligned_be16(geo_buf +
			GEOMETRY_DESC_HPB_DEVICE_MAX_ACTIVE_REGIONS);

	if (hpb_dev_info->rgn_size == 0 || hpb_dev_info->srgn_size == 0 ||
	    hpb_device_max_active_rgns == 0) {
		dev_err(hba->dev, "No HPB supported device\n");
		return -ENODEV;
	}

	return 0;
}

static int ufshpb_get_dev_info(struct ufs_hba *hba,
			       struct ufshpb_dev_info *hpb_dev_info,
			       u8 *desc_buf)
{
	int ret;
	int version;
	u8 hpb_mode;

	ret = ufshpb_read_desc(hba, QUERY_DESC_IDN_DEVICE, 0, 0, desc_buf);
	if (ret) {
		dev_err(hba->dev, "%s: idn: %d query request failed\n",
			__func__, QUERY_DESC_IDN_DEVICE);
		return -ENODEV;
	}

	hpb_mode = desc_buf[DEVICE_DESC_PARAM_HPB_CONTROL];
	if (hpb_mode == HPB_HOST_CONTROL) {
		dev_err(hba->dev, "%s: host control mode is not supported.\n",
			__func__);
		return -ENODEV;
	}

	version = get_unaligned_be16(desc_buf + DEVICE_DESC_PARAM_HPB_VER);
	if (version != HPB_SUPPORT_VERSION) {
		dev_err(hba->dev, "%s: HPB %x version is not supported.\n",
			__func__, version);
		return -ENODEV;
	}

	/*
	 * Get the number of user logical unit to check whether all
	 * scsi_device finish initialization
	 */
	hpb_dev_info->num_lu = desc_buf[DEVICE_DESC_PARAM_NUM_LU];

	ret = ufshpb_read_desc(hba, QUERY_DESC_IDN_GEOMETRY, 0, 0, desc_buf);
	if (ret) {
		dev_err(hba->dev, "%s: idn: %d query request failed\n",
			__func__, QUERY_DESC_IDN_DEVICE);
		return ret;
	}

	ret = ufshpb_get_geo_info(hba, desc_buf, hpb_dev_info);
	if (ret)
		return ret;

	return 0;
}

static int ufshpb_get_lu_info(struct ufs_hba *hba, int lun,
				    struct ufshpb_lu_info *hpb_lu_info,
				    u8 *desc_buf)
{
	u16 max_active_rgns;
	u8 lu_enable;
	int ret;

	ret = ufshpb_read_desc(hba, QUERY_DESC_IDN_UNIT, lun, 0, desc_buf);
	if (ret) {
		dev_err(hba->dev,
			"%s: idn: %d lun: %d  query request failed",
			__func__, QUERY_DESC_IDN_UNIT, lun);
		return ret;
	}

	lu_enable = desc_buf[UNIT_DESC_PARAM_LU_ENABLE];
	if (lu_enable != LU_ENABLED_HPB_FUNC)
		return -ENODEV;

	max_active_rgns = get_unaligned_be16(
			desc_buf + UNIT_DESC_HPB_LU_MAX_ACTIVE_REGIONS);
	if (!max_active_rgns) {
		dev_err(hba->dev,
			"lun %d wrong number of max active regions\n", lun);
		return -ENODEV;
	}

	hpb_lu_info->num_blocks = get_unaligned_be64(
			desc_buf + UNIT_DESC_PARAM_LOGICAL_BLK_COUNT);
	hpb_lu_info->pinned_start = get_unaligned_be16(
			desc_buf + UNIT_DESC_HPB_LU_PIN_REGION_START_OFFSET);
	hpb_lu_info->num_pinned = get_unaligned_be16(
			desc_buf + UNIT_DESC_HPB_LU_NUM_PIN_REGIONS);
	hpb_lu_info->max_active_rgns = max_active_rgns;

	return 0;
}

static void ufshpb_scan_hpb_lu(struct ufs_hba *hba,
			       struct ufshpb_dev_info *hpb_dev_info,
			       u8 *desc_buf)
{
	struct scsi_device *sdev;
	struct ufshpb_lu *hpb;
	int find_hpb_lu = 0;
	int tot_active_srgn_pages = 0;
	int pool_size;
	int ret;

	INIT_LIST_HEAD(&ufshpb_drv.lh_hpb_lu);

	shost_for_each_device(sdev, hba->host) {
		struct ufshpb_lu_info hpb_lu_info = { 0 };
		int lun = sdev->lun;

		if (lun >= hba->dev_info.max_lu_supported)
			continue;

		ret = ufshpb_get_lu_info(hba, lun, &hpb_lu_info, desc_buf);
		if (ret)
			continue;

		hpb = ufshpb_alloc_hpb_lu(hba, lun, hpb_dev_info,
					  &hpb_lu_info);
		if (!hpb)
			continue;

		tot_active_srgn_pages += hpb_lu_info.max_active_rgns *
				hpb->srgns_per_rgn * hpb->pages_per_srgn;

		hpb->sdev_ufs_lu = sdev;
		sdev->hostdata = hpb;

		list_add_tail(&hpb->list_hpb_lu, &ufshpb_drv.lh_hpb_lu);
		find_hpb_lu++;
	}

	if (!find_hpb_lu)
		return;

	ufshpb_check_hpb_reset_query(hba);

	pool_size = DIV_ROUND_UP(ufshpb_host_map_kbytes * 1024, PAGE_SIZE);
	if (pool_size > tot_active_srgn_pages) {
		dev_info(hba->dev,
			"reset pool_size to %lu KB.\n",
			tot_active_srgn_pages * PAGE_SIZE / 1024);
		mempool_resize(ufshpb_drv.ufshpb_mctx_pool,
			       tot_active_srgn_pages);
		mempool_resize(ufshpb_drv.ufshpb_page_pool,
			       tot_active_srgn_pages);
	}

	dev_set_drvdata(&hba->ufsf.hpb_dev, &ufshpb_drv);

	list_for_each_entry(hpb, &ufshpb_drv.lh_hpb_lu, list_hpb_lu) {
		dev_info(&hpb->hpb_lu_dev, "set state to present\n");
		ufshpb_set_state(hpb, HPB_PRESENT);

		if ((hpb->lu_pinned_end - hpb->lu_pinned_start) > 0) {
			dev_info(&hpb->hpb_lu_dev,
			    "loading pinned regions %d - %d\n",
			    hpb->lu_pinned_start, hpb->lu_pinned_end);
			queue_work(ufshpb_drv.ufshpb_wq,
				&hpb->map_work);
		}
	}
}

static int ufshpb_probe(struct device *dev)
{
	struct ufs_hba *hba;
	struct ufsf_feature_info *ufsf;
	struct ufshpb_dev_info hpb_dev_info = { 0 };
	char *desc_buf;
	int ret;

	if (dev->type != &ufshpb_dev_type)
		return -ENODEV;

	ufsf = container_of(dev, struct ufsf_feature_info, hpb_dev);
	hba = container_of(ufsf, struct ufs_hba, ufsf);

	desc_buf = kzalloc(QUERY_DESC_MAX_SIZE, GFP_KERNEL);
	if (!desc_buf)
		goto release_desc_buf;

	ret = ufshpb_get_dev_info(hba, &hpb_dev_info, desc_buf);
	if (ret)
		goto release_desc_buf;

	/*
	 * Because HPB driver uses scsi_device data structure,
	 * we should wait at this point until finishing initialization of all
	 * scsi devices. Even if timeout occurs, HPB driver will search
	 * the scsi_device list on struct scsi_host (shost->__host list_head)
	 * and can find out HPB logical units in all scsi_devices
	 */
	wait_event_timeout(hba->ufsf.sdev_wait,
			   (atomic_read(&hba->ufsf.slave_conf_cnt)
				== hpb_dev_info.num_lu),
			   SDEV_WAIT_TIMEOUT);

	ufshpb_issue_hpb_reset_query(hba);

	dev_dbg(hba->dev, "ufshpb: slave count %d, lu count %d\n",
		atomic_read(&hba->ufsf.slave_conf_cnt), hpb_dev_info.num_lu);

	ufshpb_scan_hpb_lu(hba, &hpb_dev_info, desc_buf);

release_desc_buf:
	kfree(desc_buf);
	return 0;
}

static int ufshpb_remove(struct device *dev)
{
	struct ufshpb_lu *hpb, *n_hpb;
	struct ufsf_feature_info *ufsf;
	struct scsi_device *sdev;

	ufsf = container_of(dev, struct ufsf_feature_info, hpb_dev);

	dev_set_drvdata(&ufsf->hpb_dev, NULL);

	list_for_each_entry_safe(hpb, n_hpb, &ufshpb_drv.lh_hpb_lu,
				 list_hpb_lu) {
		ufshpb_set_state(hpb, HPB_FAILED);

		sdev = hpb->sdev_ufs_lu;
		sdev->hostdata = NULL;

		ufshpb_cancel_jobs(hpb);

		device_del(&hpb->hpb_lu_dev);

		dev_info(&hpb->hpb_lu_dev, "hpb_lu_dev refcnt %d\n",
			 kref_read(&hpb->hpb_lu_dev.kobj.kref));
		put_device(&hpb->hpb_lu_dev);
	}
	dev_info(dev, "ufshpb: remove success\n");

	return 0;
}

static struct ufshpb_driver ufshpb_drv = {
	.drv = {
		.name = "ufshpb_driver",
		.owner = THIS_MODULE,
		.probe = ufshpb_probe,
		.remove = ufshpb_remove,
		.bus = &ufsf_bus_type,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
	.ufshpb_ops = {
		.reset = ufshpb_reset,
		.reset_host = ufshpb_reset_host,
		.suspend = ufshpb_suspend,
		.resume = ufshpb_resume,
		.rsp_upiu = ufshpb_rsp_upiu,
	},
};

module_param(ufshpb_host_map_kbytes, uint, 0644);
MODULE_PARM_DESC(ufshpb_host_map_kbytes,
	 "ufshpb host mapping memory kilo-bytes for ufshpb memory-pool");

static int __init ufshpb_init(void)
{
	int ret;
	unsigned int pool_size;

	ufshpb_drv.ufshpb_mctx_cache = kmem_cache_create("ufshpb_mctx_cache",
					sizeof(struct ufshpb_map_ctx),
					0, 0, NULL);
	if (!ufshpb_drv.ufshpb_mctx_cache) {
		pr_err("ufshpb: cannot init mctx cache\n");
		return -ENOMEM;
	}

	pool_size = DIV_ROUND_UP(ufshpb_host_map_kbytes * 1024, PAGE_SIZE);
	pr_info("%s:%d ufshpb_host_map_kbytes %u pool_size %u\n",
	       __func__, __LINE__, ufshpb_host_map_kbytes, pool_size);

	ufshpb_drv.ufshpb_mctx_pool = mempool_create_slab_pool(
				     pool_size, ufshpb_drv.ufshpb_mctx_cache);
	if (!ufshpb_drv.ufshpb_mctx_pool) {
		pr_err("ufshpb: cannot init mctx pool\n");
		ret = -ENOMEM;
		goto release_mctx_cache;
	}

	ufshpb_drv.ufshpb_page_pool = mempool_create_page_pool(pool_size, 0);
	if (!ufshpb_drv.ufshpb_page_pool) {
		pr_err("ufshpb: cannot init page pool\n");
		ret = -ENOMEM;
		goto release_mctx_pool;
	}

	ufshpb_drv.ufshpb_wq = alloc_workqueue("ufshpb-wq",
					WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!ufshpb_drv.ufshpb_wq) {
		pr_err("ufshpb: alloc workqueue failed\n");
		ret = -ENOMEM;
		goto release_page_pool;
	}

	ret = driver_register(&ufshpb_drv.drv);
	if (ret) {
		pr_err("ufshpb: driver register failed\n");
		goto release_wq;
	}

	return 0;
release_wq:
	destroy_workqueue(ufshpb_drv.ufshpb_wq);
release_page_pool:
	mempool_destroy(ufshpb_drv.ufshpb_page_pool);
release_mctx_pool:
	mempool_destroy(ufshpb_drv.ufshpb_mctx_pool);
release_mctx_cache:
	kmem_cache_destroy(ufshpb_drv.ufshpb_mctx_cache);
	return ret;
}

static void __exit ufshpb_exit(void)
{
	driver_unregister(&ufshpb_drv.drv);

	mempool_destroy(ufshpb_drv.ufshpb_page_pool);
	mempool_destroy(ufshpb_drv.ufshpb_mctx_pool);
	kmem_cache_destroy(ufshpb_drv.ufshpb_mctx_cache);

	destroy_workqueue(ufshpb_drv.ufshpb_wq);
}

MODULE_AUTHOR("Yongmyong Lee <ymhungry.lee@samsung.com>");
MODULE_AUTHOR("Jinyoung Choi <j-young.choi@samsung.com>");
MODULE_DESCRIPTION("UFS Host Performance Booster Driver");

module_init(ufshpb_init);
module_exit(ufshpb_exit);
MODULE_LICENSE("GPL");
