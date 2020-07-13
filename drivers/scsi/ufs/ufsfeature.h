/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Universal Flash Storage Feature Support
 *
 * Copyright (C) 2017-2018 Samsung Electronics Co., Ltd.
 *
 * Authors:
 *	Yongmyung Lee <ymhungry.lee@samsung.com>
 *	Jinyoung Choi <j-young.choi@samsung.com>
 */

#ifndef _UFSFEATURE_H_
#define _UFSFEATURE_H_

#define HPB_SUPPORTED_VERSION			0x0310

struct ufs_hba;
struct ufshcd_lrb;

/**
 * struct ufsf_operation - UFS feature specific callbacks
 * @prep_fn: called after construct upiu structure. The prep_fn should work
 *	     properly even if it processes the same SCSI command multiple
 *	     times by requeuing.
 * @reset: called after probing hba
 * @reset_host: called before ufshcd_host_reset_and_restore
 * @suspend: called before ufshcd_suspend
 * @resume: called after ufshcd_resume
 * @rsp_upiu: called in ufshcd_transfer_rsp_status with SAM_STAT_GOOD state
 */
struct ufsf_operation {
	void (*prep_fn)(struct ufs_hba *hba, struct ufshcd_lrb *lrbp);
	void (*reset)(struct ufs_hba *hba);
	void (*reset_host)(struct ufs_hba *hba);
	void (*suspend)(struct ufs_hba *hba);
	void (*resume)(struct ufs_hba *hba);
	void (*rsp_upiu)(struct ufs_hba *hba, struct ufshcd_lrb *lrbp);
};

struct ufshpb_driver {
	struct device_driver drv;
	struct list_head lh_hpb_lu;

	struct ufsf_operation ufshpb_ops;

	/* memory management */
	struct kmem_cache *ufshpb_mctx_cache;
	mempool_t *ufshpb_mctx_pool;
	mempool_t *ufshpb_page_pool;

	struct workqueue_struct *ufshpb_wq;
};

struct ufsf_feature_info {
	atomic_t slave_conf_cnt;
	wait_queue_head_t sdev_wait;
	struct device hpb_dev;
};

void ufsf_slave_configure(struct ufs_hba *hba, struct scsi_device *sdev);
void ufsf_scan_features(struct ufs_hba *hba);
void ufsf_ops_prep_fn(struct ufs_hba *hba, struct ufshcd_lrb *lrbp);
void ufsf_ops_rsp_upiu(struct ufs_hba *hba, struct ufshcd_lrb *lrbp);
void ufsf_ops_reset_host(struct ufs_hba *hba);
void ufsf_ops_reset(struct ufs_hba *hba);
void ufsf_ops_suspend(struct ufs_hba *hba);
void ufsf_ops_resume(struct ufs_hba *hba);

#endif /* End of Header */
