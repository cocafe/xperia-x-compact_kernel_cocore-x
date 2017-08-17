/* Copyright (c) 2014-2015, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of Code Aurora Forum, Inc. nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Alternatively, and instead of the terms immediately above, this
 * software may be relicensed by the recipient at their option under the
 * terms of the GNU General Public License version 2 ("GPL") and only
 * version 2.  If the recipient chooses to relicense the software under
 * the GPL, then the recipient shall replace all of the text immediately
 * above and including this paragraph with the text immediately below
 * and between the words START OF ALTERNATE GPL TERMS and END OF
 * ALTERNATE GPL TERMS and such notices and license terms shall apply
 * INSTEAD OF the notices and licensing terms given above.
 *
 * START OF ALTERNATE GPL TERMS
 *
 * Copyright (c) 2014-2015, The Linux Foundation. All rights reserved.
 *
 * This software was originally licensed under the Code Aurora Forum
 * Inc. Dual BSD/GPL License version 1.1 and relicensed as permitted
 * under the terms thereof by a recipient under the General Public
 * License Version 2.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * END OF ALTERNATE GPL TERMS
 *
 */
#ifndef __CRYPTO_MSM_QCEDEVI_H
#define __CRYPTO_MSM_QCEDEVI_H

#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <crypto/hash.h>
#include <linux/platform_data/qcom_crypto_device.h>
#include <linux/fips_status.h>
#include "qce.h"

#define CACHE_LINE_SIZE 32
#define CE_SHA_BLOCK_SIZE SHA256_BLOCK_SIZE

/* FIPS global status variable */
// extern enum fips_status g_fips140_status;


enum qcedev_crypto_oper_type {
	QCEDEV_CRYPTO_OPER_CIPHER = 0,
	QCEDEV_CRYPTO_OPER_SHA = 1,
	QCEDEV_CRYPTO_OPER_LAST
};

struct qcedev_handle;

struct qcedev_cipher_req {
	struct ablkcipher_request creq;
	void *cookie;
};

struct qcedev_sha_req {
	struct ahash_request sreq;
	void *cookie;
};

struct	qcedev_sha_ctxt {
	uint32_t	auth_data[4];
	uint8_t	digest[QCEDEV_MAX_SHA_DIGEST];
	uint32_t	diglen;
	uint8_t	trailing_buf[64];
	uint32_t	trailing_buf_len;
	uint8_t	first_blk;
	uint8_t	last_blk;
	uint8_t	authkey[QCEDEV_MAX_SHA_BLOCK_SIZE];
	bool		init_done;
};

struct qcedev_async_req {
	struct list_head			list;
	struct completion			complete;
	enum qcedev_crypto_oper_type		op_type;
	union {
		struct qcedev_cipher_op_req	cipher_op_req;
		struct qcedev_sha_op_req	sha_op_req;
	};

	union {
		struct qcedev_cipher_req	cipher_req;
		struct qcedev_sha_req		sha_req;
	};
	struct qcedev_handle			*handle;
	int					err;
};

/**********************************************************************
 * Register ourselves as a misc device to be able to access the dev driver
 * from userspace. */

#define QCEDEV_DEV	"qcedev"

struct qcedev_control {

	/* CE features supported by platform */
	struct msm_ce_hw_support platform_support;

	uint32_t ce_lock_count;
	uint32_t high_bw_req_count;

	/* CE features/algorithms supported by HW engine*/
	struct ce_hw_support ce_support;

	uint32_t  bus_scale_handle;

	/* misc device */
	struct miscdevice miscdevice;

	/* qce handle */
	void *qce;

	/* platform device */
	struct platform_device *pdev;

	unsigned magic;

	struct list_head ready_commands;
	struct qcedev_async_req *active_command;
	spinlock_t lock;
	struct tasklet_struct done_tasklet;
};

struct qcedev_handle {
	/* qcedev control handle */
	struct qcedev_control *cntl;
	/* qce internal sha context*/
	struct qcedev_sha_ctxt sha_ctxt;
};

void qcedev_cipher_req_cb(void *cookie, unsigned char *icv,
	unsigned char *iv, int ret);

void qcedev_sha_req_cb(void *cookie, unsigned char *digest,
	unsigned char *authdata, int ret);

extern int _do_msm_fips_drbg_init(void *rng_dev);

#ifdef CONFIG_FIPS_ENABLE

/*
 * Self test for Cipher algorithms
 */
int _fips_qcedev_cipher_selftest(struct qcedev_control *podev);

/*
 * Self test for SHA / HMAC
 */

int _fips_qcedev_sha_selftest(struct qcedev_control *podev);

/*
 * Update FIPs Global status Status
 */
static inline enum fips_status _fips_update_status(enum fips_status status)
{
	return ((status == FIPS140_STATUS_PASS) ||
		(status == FIPS140_STATUS_QCRYPTO_ALLOWED)) ?
		FIPS140_STATUS_QCRYPTO_ALLOWED :
		FIPS140_STATUS_FAIL;
}

#else

static inline int _fips_qcedev_cipher_selftest(struct qcedev_control *podev)
{
	return 0;
}
static inline int _fips_qcedev_sha_selftest(struct qcedev_control *podev)
{
	return 0;
}

static inline enum fips_status _fips_update_status(enum fips_status status)
{
	return FIPS140_STATUS_NA;
}

#endif  /* CONFIG_FIPS_ENABLE */

#endif  /* __CRYPTO_MSM_QCEDEVI_H */
