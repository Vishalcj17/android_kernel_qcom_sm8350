// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2017, 2019 The Linux Foundation. All rights reserved.
 */

#define pr_fmt(fmt) "OPLUS_CHG[CFG]: %s[%d]: " fmt, __func__, __LINE__

#include <linux/errno.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/crypto.h>
#include "oplus_chg_comm.h"
#include "oplus_chg_wls.h"
#include "oplus_chg_cfg.h"

static union { char c[4]; unsigned long l; } endian_test = { { 'l', '?', '?', 'b' } };
#define ENDIANNESS ((char)endian_test.l)

struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc)
		return ERR_PTR(-ENOMEM);
	sdesc->shash.tfm = alg;
	return sdesc;
}

static int calc_hash(struct crypto_shash *alg, const unsigned char *data,
		     unsigned int datalen, unsigned char *digest)
{
	struct sdesc *sdesc;
	int ret;

	sdesc = init_sdesc(alg);
	if (IS_ERR(sdesc)) {
		pr_info("can't alloc sdesc\n");
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
	kfree(sdesc);
	return ret;
}

static u32 oplus_chg_cfg_get_data_size(struct oplus_chg_param_head *param_head)
{
	struct oplus_chg_cfg_data_head *data_head;
	u32 index;

	for (index = 0; index < param_head->size; ) {
		data_head = (struct oplus_chg_cfg_data_head *)(param_head->data + index);
		if (data_head->magic != OPLUS_CHG_CFG_MAGIC) {
			pr_err("data magic error\n");
			return 0;
		}
		index += data_head->size + sizeof(struct oplus_chg_cfg_data_head);
	}

	return index;
}

int oplus_chg_check_cfg_data(void *buf)
{
	struct oplus_chg_cfg_head *cfg_head;
	struct oplus_chg_param_head *param_head;
	struct crypto_shash *alg;
	char *hash_alg_name = "sha256";
	unsigned char digest[32];
	int rc;

	if (buf == NULL) {
		pr_err("data buf is null\n");
		return -EINVAL;
	}

	cfg_head = (struct oplus_chg_cfg_head *)buf;

	if (cfg_head->magic != OPLUS_CHG_CFG_MAGIC ||
	    cfg_head->head_size != sizeof(struct oplus_chg_cfg_head)) {
		pr_err("cfg head error, magic=0x%08x, size=%d\n", cfg_head->magic, cfg_head->head_size);
		return -EINVAL;
	}

	param_head = (struct oplus_chg_param_head *)((unsigned char *)buf + cfg_head->param_index[OPLUS_CHG_USB_PARAM]);
	if (param_head->size != oplus_chg_cfg_get_data_size(param_head)) {
		pr_err("usb charge parameter length error, len=%d\n", oplus_chg_cfg_get_data_size(param_head));
		return -EINVAL;
	}
	param_head = (struct oplus_chg_param_head *)((unsigned char *)buf + cfg_head->param_index[OPLUS_CHG_WLS_PARAM]);
	if (param_head->size != oplus_chg_cfg_get_data_size(param_head)) {
		pr_err("wireless charge parameter length error, len=%d\n", oplus_chg_cfg_get_data_size(param_head));
		return -EINVAL;
	}
	param_head = (struct oplus_chg_param_head *)((unsigned char *)buf + cfg_head->param_index[OPLUS_CHG_COMM_PARAM]);
	if (param_head->size != oplus_chg_cfg_get_data_size(param_head)) {
		pr_err("common parameter length error, len=%d\n", oplus_chg_cfg_get_data_size(param_head));
		return -EINVAL;
	}
	param_head = (struct oplus_chg_param_head *)((unsigned char *)buf + cfg_head->param_index[OPLUS_CHG_BATT_PARAM]);
	if (param_head->size != oplus_chg_cfg_get_data_size(param_head)) {
		pr_err("battery parameter length error, len=%d\n", oplus_chg_cfg_get_data_size(param_head));
		return -EINVAL;
	}

	alg = crypto_alloc_shash(hash_alg_name, 0, 0);
	if (IS_ERR(alg)) {
		pr_err("can't alloc alg %s\n", hash_alg_name);
		return PTR_ERR(alg);
	}
	rc = calc_hash(alg, (unsigned char *)buf + cfg_head->head_size, cfg_head->size, digest);
	if (rc < 0) {
		pr_err("Configuration file digest calculation failed, rc=%d\n", rc);
		return rc;
	}
	crypto_free_shash(alg);

	return 0;
}

void *oplus_chg_get_param(void *buf, enum oplus_chg_param_type type)
{
	struct oplus_chg_cfg_head *cfg_head;
	struct oplus_chg_param_head *param_head;

	cfg_head = (struct oplus_chg_cfg_head *)buf;
	param_head = (struct oplus_chg_param_head *)((unsigned char *)buf + cfg_head->param_index[type]);

	if (param_head->magic != OPLUS_CHG_CFG_MAGIC)
		return NULL;
	if (param_head->size == 0)
		return NULL;
	if (param_head->type != type)
		return NULL;
	if (param_head->size != oplus_chg_cfg_get_data_size(param_head))
		return NULL;

	return (void *)param_head->data;
}

int oplus_chg_cfg_load_param(void *src, enum oplus_chg_param_type type, u8 *out_buf)
{
	struct oplus_chg_cfg_head *cfg_head;
	struct oplus_chg_param_head *param_head;
	struct oplus_chg_cfg_data_head *data_head;
	uint32_t data_index;

	if (src == NULL) {
		pr_err("src is NULL\n");
		return -ENODATA;
	}
	if (out_buf == NULL) {
		pr_err("out_buf is NULL\n");
		return -EINVAL;
	}
	cfg_head = (struct oplus_chg_cfg_head *)src;
	param_head = (struct oplus_chg_param_head *)((unsigned char *)src + cfg_head->param_index[type]);

	if (param_head->magic != OPLUS_CHG_CFG_MAGIC) {
		pr_err("param(=%d) magic error\n", type);
		return -EINVAL;
	}
	if (param_head->size == 0)
		return 0;
	if (param_head->type != type) {
		pr_err("param(=%d) type(=%d) error\n", type, param_head->type);
		return -EINVAL;
	}
	if (ENDIANNESS == 'b') {
		pr_err("Big-endian mode is temporarily not supported\n");
		return -EINVAL;
	}

	for (data_index = 0; data_index < param_head->size; ) {
		data_head = (struct oplus_chg_cfg_data_head *)(param_head->data + data_index);
		if (data_head->magic != OPLUS_CHG_CFG_MAGIC) {
			pr_err("data magic error\n");
			return -EINVAL;
		}
		memcpy(out_buf + data_head->index, data_head->data, data_head->size);
		data_index += data_head->size + sizeof(struct oplus_chg_cfg_data_head);
	}

	if (data_index != param_head->size) {
		pr_err("param(=%d) size error\n", type);
		return -EINVAL;
	}

	return 0;
}
