// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Universal Flash Storage Feature Support
 *
 * Copyright (C) 2017-2018 Samsung Electronics Co., Ltd.
 *
 * Authors:
 *	Yongmyung Lee <ymhungry.lee@samsung.com>
 *	Jinyoung Choi <j-young.choi@samsung.com>
 */

#include "ufshcd.h"
#include "ufsfeature.h"

inline void ufsf_slave_configure(struct ufs_hba *hba,
				 struct scsi_device *sdev)
{
	/* skip well-known LU */
	if (sdev->lun >= UFS_UPIU_MAX_UNIT_NUM_ID)
		return;

	if (!(hba->dev_info.b_ufs_feature_sup & UFS_DEV_HPB_SUPPORT))
		return;

	atomic_inc(&hba->ufsf.slave_conf_cnt);

	wake_up(&hba->ufsf.sdev_wait);
}

inline void ufsf_ops_prep_fn(struct ufs_hba *hba, struct ufshcd_lrb *lrbp)
{
	struct ufshpb_driver *ufshpb_drv;

	ufshpb_drv = dev_get_drvdata(&hba->ufsf.hpb_dev);

	if (ufshpb_drv && ufshpb_drv->ufshpb_ops.prep_fn)
		ufshpb_drv->ufshpb_ops.prep_fn(hba, lrbp);
}

inline void ufsf_ops_rsp_upiu(struct ufs_hba *hba, struct ufshcd_lrb *lrbp)
{
	struct ufshpb_driver *ufshpb_drv;

	ufshpb_drv = dev_get_drvdata(&hba->ufsf.hpb_dev);

	if (ufshpb_drv && ufshpb_drv->ufshpb_ops.rsp_upiu)
		ufshpb_drv->ufshpb_ops.rsp_upiu(hba, lrbp);
}

inline void ufsf_ops_reset_host(struct ufs_hba *hba)
{
	struct ufshpb_driver *ufshpb_drv;

	ufshpb_drv = dev_get_drvdata(&hba->ufsf.hpb_dev);

	if (ufshpb_drv && ufshpb_drv->ufshpb_ops.reset_host)
		ufshpb_drv->ufshpb_ops.reset_host(hba);
}

inline void ufsf_ops_reset(struct ufs_hba *hba)
{
	struct ufshpb_driver *ufshpb_drv;

	ufshpb_drv = dev_get_drvdata(&hba->ufsf.hpb_dev);

	if (ufshpb_drv && ufshpb_drv->ufshpb_ops.reset)
		ufshpb_drv->ufshpb_ops.reset(hba);
}

inline void ufsf_ops_suspend(struct ufs_hba *hba)
{
	struct ufshpb_driver *ufshpb_drv;

	ufshpb_drv = dev_get_drvdata(&hba->ufsf.hpb_dev);

	if (ufshpb_drv && ufshpb_drv->ufshpb_ops.suspend)
		ufshpb_drv->ufshpb_ops.suspend(hba);
}

inline void ufsf_ops_resume(struct ufs_hba *hba)
{
	struct ufshpb_driver *ufshpb_drv;

	ufshpb_drv = dev_get_drvdata(&hba->ufsf.hpb_dev);

	if (ufshpb_drv && ufshpb_drv->ufshpb_ops.resume)
		ufshpb_drv->ufshpb_ops.resume(hba);
}

struct device_type ufshpb_dev_type = {
	.name = "ufshpb_device"
};
EXPORT_SYMBOL(ufshpb_dev_type);

static int ufsf_bus_match(struct device *dev,
			 struct device_driver *gendrv)
{
	if (dev->type == &ufshpb_dev_type)
		return 1;

	return 0;
}

struct bus_type ufsf_bus_type = {
	.name = "ufsf_bus",
	.match = ufsf_bus_match,
};
EXPORT_SYMBOL(ufsf_bus_type);

static void ufsf_dev_release(struct device *dev)
{
	put_device(dev->parent);
}

void ufsf_scan_features(struct ufs_hba *hba)
{
	int ret;

	init_waitqueue_head(&hba->ufsf.sdev_wait);
	atomic_set(&hba->ufsf.slave_conf_cnt, 0);

	if (hba->dev_info.wspecversion >= HPB_SUPPORTED_VERSION &&
	    (hba->dev_info.b_ufs_feature_sup & UFS_DEV_HPB_SUPPORT)) {
		device_initialize(&hba->ufsf.hpb_dev);

		hba->ufsf.hpb_dev.bus = &ufsf_bus_type;
		hba->ufsf.hpb_dev.type = &ufshpb_dev_type;
		hba->ufsf.hpb_dev.parent = get_device(hba->dev);
		hba->ufsf.hpb_dev.release = ufsf_dev_release;

		dev_set_name(&hba->ufsf.hpb_dev, "ufshpb");
		ret = device_add(&hba->ufsf.hpb_dev);
		if (ret)
			dev_warn(hba->dev, "ufshpb: failed to add device\n");
	}
}

static int __init ufsf_init(void)
{
	int ret;

	ret = bus_register(&ufsf_bus_type);
	if (ret)
		pr_err("%s bus_register failed\n", __func__);

	return ret;
}
device_initcall(ufsf_init);
