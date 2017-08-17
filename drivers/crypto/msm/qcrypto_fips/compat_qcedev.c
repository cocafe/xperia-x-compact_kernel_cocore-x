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
#define pr_fmt(fmt) "COMPAT-QCEDEV: %s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/qcedev.h>
#include <linux/compat.h>
#include <linux/compat_qcedev.h>

#include "qcrypto_wrapper.h"

static int compat_get_qcedev_pmem_info(
		struct compat_qcedev_pmem_info __user *pmem32,
		struct qcedev_pmem_info __user *pmem)
{
	compat_ulong_t offset;
	compat_int_t fd_src;
	compat_int_t fd_dst;
	int err = 0, i = 0;
	uint32_t len;

	err |= get_user(fd_src, &pmem32->fd_src);
	err |= put_user(fd_src, &pmem->fd_src);

	for (i = 0; i < QCEDEV_MAX_BUFFERS; i++) {
		err |= get_user(offset, &pmem32->src[i].offset);
		err |= put_user(offset, &pmem->src[i].offset);
		err |= get_user(len, &pmem32->src[i].len);
		err |= put_user(len, &pmem->src[i].len);
	}

	err |= get_user(fd_dst, &pmem32->fd_dst);
	err |= put_user(fd_dst, &pmem->fd_dst);

	for (i = 0; i < QCEDEV_MAX_BUFFERS; i++) {
		err |= get_user(offset, &pmem32->dst[i].offset);
		err |= put_user(offset, &pmem->dst[i].offset);
		err |= get_user(len, &pmem32->dst[i].len);
		err |= put_user(len, &pmem->dst[i].len);
	}

	return err;
}

static int compat_put_qcedev_pmem_info(
		struct compat_qcedev_pmem_info __user *pmem32,
		struct qcedev_pmem_info __user *pmem)
{
	compat_ulong_t offset;
	compat_int_t fd_src;
	compat_int_t fd_dst;
	int err = 0, i = 0;
	uint32_t len;

	err |= get_user(fd_src, &pmem->fd_src);
	err |= put_user(fd_src, &pmem32->fd_src);

	for (i = 0; i < QCEDEV_MAX_BUFFERS; i++) {
		err |= get_user(offset, &pmem->src[i].offset);
		err |= put_user(offset, &pmem32->src[i].offset);
		err |= get_user(len, &pmem->src[i].len);
		err |= put_user(len, &pmem32->src[i].len);
	}

	err |= get_user(fd_dst, &pmem->fd_dst);
	err |= put_user(fd_dst, &pmem32->fd_dst);

	for (i = 0; i < QCEDEV_MAX_BUFFERS; i++) {
		err |= get_user(offset, &pmem->dst[i].offset);
		err |= put_user(offset, &pmem32->dst[i].offset);
		err |= get_user(len, &pmem->dst[i].len);
		err |= put_user(len, &pmem32->dst[i].len);
	}

	return err;
}

static int compat_get_qcedev_vbuf_info(
		struct compat_qcedev_vbuf_info __user *vbuf32,
		struct qcedev_vbuf_info __user *vbuf)
{
	compat_uptr_t vaddr;
	int err = 0, i = 0;
	uint32_t len;

	for (i = 0; i < QCEDEV_MAX_BUFFERS; i++) {
		err |= get_user(vaddr, &vbuf32->src[i].vaddr);
		vbuf->src[i].vaddr = NULL;
		err |= put_user(vaddr, (compat_uptr_t *)&vbuf->src[i].vaddr);
		err |= get_user(len, &vbuf32->src[i].len);
		err |= put_user(len, &vbuf->src[i].len);
	}

	for (i = 0; i < QCEDEV_MAX_BUFFERS; i++) {
		err |= get_user(vaddr, &vbuf32->dst[i].vaddr);
		vbuf->dst[i].vaddr = NULL;
		err |= put_user(vaddr, (compat_uptr_t *)&vbuf->dst[i].vaddr);
		err |= get_user(len, &vbuf32->dst[i].len);
		err |= put_user(len, &vbuf->dst[i].len);
	}
	return err;
}

static int compat_put_qcedev_vbuf_info(
		struct compat_qcedev_vbuf_info __user *vbuf32,
		struct qcedev_vbuf_info __user *vbuf)
{
	compat_uptr_t vaddr;
	int err = 0, i = 0;
	uint32_t len;

	for (i = 0; i < QCEDEV_MAX_BUFFERS; i++) {
		err |= get_user(vaddr, (compat_uptr_t *)&vbuf->src[i].vaddr);
		vbuf32->src[i].vaddr = 0;
		err |= put_user(vaddr, &vbuf32->src[i].vaddr);
		err |= get_user(len, &vbuf->src[i].len);
		err |= put_user(len, &vbuf32->src[i].len);
	}

	for (i = 0; i < QCEDEV_MAX_BUFFERS; i++) {
		err |= get_user(vaddr, (compat_uptr_t *)&vbuf->dst[i].vaddr);
		vbuf32->dst[i].vaddr = 0;
		err |= put_user(vaddr, &vbuf32->dst[i].vaddr);
		err |= get_user(len, &vbuf->dst[i].len);
		err |= put_user(len, &vbuf32->dst[i].len);
	}
	return err;
}

static int compat_get_qcedev_cipher_op_req(
		struct compat_qcedev_cipher_op_req __user *data32,
		struct qcedev_cipher_op_req __user *data)
{
	enum qcedev_cipher_mode_enum mode;
	enum qcedev_cipher_alg_enum alg;
	compat_ulong_t byteoffset;
	enum qcedev_oper_enum op;
	compat_ulong_t data_len;
	compat_ulong_t encklen;
	compat_ulong_t entries;
	compat_ulong_t ivlen;
	uint8_t in_place_op;
	int err = 0, i = 0;
	uint8_t use_pmem;
	uint8_t enckey;
	uint8_t iv;

	err |= get_user(use_pmem, &data32->use_pmem);
	err |= put_user(use_pmem, &data->use_pmem);

	if (use_pmem)
		err |= compat_get_qcedev_pmem_info(&data32->pmem, &data->pmem);
	else
		err |= compat_get_qcedev_vbuf_info(&data32->vbuf, &data->vbuf);

	err |= get_user(entries, &data32->entries);
	err |= put_user(entries, &data->entries);
	err |= get_user(data_len, &data32->data_len);
	err |= put_user(data_len, &data->data_len);
	err |= get_user(in_place_op, &data32->in_place_op);
	err |= put_user(in_place_op, &data->in_place_op);

	for (i = 0; i < QCEDEV_MAX_KEY_SIZE; i++) {
		err |= get_user(enckey, &(data32->enckey[i]));
		err |= put_user(enckey, &(data->enckey[i]));
	}

	err |= get_user(encklen, &data32->encklen);
	err |= put_user(encklen, &data->encklen);

	for (i = 0; i < QCEDEV_MAX_IV_SIZE; i++) {
		err |= get_user(iv, &(data32->iv[i]));
		err |= put_user(iv, &(data->iv[i]));
	}

	err |= get_user(ivlen, &data32->ivlen);
	err |= put_user(ivlen, &data->ivlen);
	err |= get_user(byteoffset, &data32->byteoffset);
	err |= put_user(byteoffset, &data->byteoffset);
	err |= get_user(alg, &data32->alg);
	err |= put_user(alg, &data->alg);
	err |= get_user(mode, &data32->mode);
	err |= put_user(mode, &data->mode);
	err |= get_user(op, &data32->op);
	err |= put_user(op, &data->op);

	return err;
}

static int compat_put_qcedev_cipher_op_req(
		struct compat_qcedev_cipher_op_req __user *data32,
		struct qcedev_cipher_op_req __user *data)
{
	enum qcedev_cipher_mode_enum mode;
	enum qcedev_cipher_alg_enum alg;
	compat_ulong_t byteoffset;
	enum qcedev_oper_enum op;
	compat_ulong_t data_len;
	compat_ulong_t encklen;
	compat_ulong_t entries;
	compat_ulong_t ivlen;
	uint8_t in_place_op;
	int err = 0, i = 0;
	uint8_t use_pmem;
	uint8_t enckey;
	uint8_t iv;

	err |= get_user(use_pmem, &data->use_pmem);
	err |= put_user(use_pmem, &data32->use_pmem);

	if (use_pmem)
		err |= compat_put_qcedev_pmem_info(&data32->pmem, &data->pmem);
	else
		err |= compat_put_qcedev_vbuf_info(&data32->vbuf, &data->vbuf);

	err |= get_user(entries, &data->entries);
	err |= put_user(entries, &data32->entries);
	err |= get_user(data_len, &data->data_len);
	err |= put_user(data_len, &data32->data_len);
	err |= get_user(in_place_op, &data->in_place_op);
	err |= put_user(in_place_op, &data32->in_place_op);

	for (i = 0; i < QCEDEV_MAX_KEY_SIZE; i++) {
		err |= get_user(enckey, &(data->enckey[i]));
		err |= put_user(enckey, &(data32->enckey[i]));
	}

	err |= get_user(encklen, &data->encklen);
	err |= put_user(encklen, &data32->encklen);

	for (i = 0; i < QCEDEV_MAX_IV_SIZE; i++) {
		err |= get_user(iv, &(data->iv[i]));
		err |= put_user(iv, &(data32->iv[i]));
	}

	err |= get_user(ivlen, &data->ivlen);
	err |= put_user(ivlen, &data32->ivlen);
	err |= get_user(byteoffset, &data->byteoffset);
	err |= put_user(byteoffset, &data32->byteoffset);
	err |= get_user(alg, &data->alg);
	err |= put_user(alg, &data32->alg);
	err |= get_user(mode, &data->mode);
	err |= put_user(mode, &data32->mode);
	err |= get_user(op, &data->op);
	err |= put_user(op, &data32->op);

	return err;
}

static int compat_get_qcedev_sha_op_req(
		struct compat_qcedev_sha_op_req __user *data32,
		struct qcedev_sha_op_req __user *data)
{
	enum qcedev_sha_alg_enum alg;
	compat_ulong_t authklen;
	compat_ulong_t data_len;
	compat_ulong_t entries;
	compat_ulong_t diglen;
	compat_uptr_t authkey;
	compat_uptr_t vaddr;
	int err = 0, i = 0;
	uint8_t digest;
	uint32_t len;

	for (i = 0; i < QCEDEV_MAX_BUFFERS; i++) {
		err |= get_user(vaddr, &data32->data[i].vaddr);
		data->data[i].vaddr = 0;
		err |= put_user(vaddr, (compat_uptr_t *)&data->data[i].vaddr);
		err |= get_user(len, &data32->data[i].len);
		err |= put_user(len, &data->data[i].len);
	}

	err |= get_user(entries, &data32->entries);
	err |= put_user(entries, &data->entries);
	err |= get_user(data_len, &data32->data_len);
	err |= put_user(data_len, &data->data_len);

	for (i = 0; i < QCEDEV_MAX_SHA_DIGEST; i++) {
		err |= get_user(digest, &(data32->digest[i]));
		err |= put_user(digest, &(data->digest[i]));
	}

	err |= get_user(diglen, &data32->diglen);
	err |= put_user(diglen, &data->diglen);
	err |= get_user(authkey, &data32->authkey);
	data->authkey = NULL;
	err |= put_user(authkey, (compat_uptr_t *)&data->authkey);
	err |= get_user(authklen, &data32->authklen);
	err |= put_user(authklen, &data->authklen);
	err |= get_user(alg, &data32->alg);
	err |= put_user(alg, &data->alg);

	return err;
}

static int compat_put_qcedev_sha_op_req(
		struct compat_qcedev_sha_op_req __user *data32,
		struct qcedev_sha_op_req __user *data)
{
	enum qcedev_sha_alg_enum alg;
	compat_ulong_t authklen;
	compat_ulong_t data_len;
	compat_ulong_t entries;
	compat_ulong_t diglen;
	compat_uptr_t authkey;
	compat_uptr_t vaddr;
	int err = 0, i = 0;
	uint8_t digest;
	uint32_t len;

	for (i = 0; i < QCEDEV_MAX_BUFFERS; i++) {
		err |= get_user(vaddr, (compat_uptr_t *)&data->data[i].vaddr);
		data32->data[i].vaddr = 0;
		err |= put_user(vaddr, &data32->data[i].vaddr);
		err |= get_user(len, &data->data[i].len);
		err |= put_user(len, &data32->data[i].len);
	}

	err |= get_user(entries, &data->entries);
	err |= put_user(entries, &data32->entries);
	err |= get_user(data_len, &data->data_len);
	err |= put_user(data_len, &data32->data_len);

	for (i = 0; i < QCEDEV_MAX_SHA_DIGEST; i++) {
		err |= get_user(digest, &(data->digest[i]));
		err |= put_user(digest, &(data32->digest[i]));
	}

	err |= get_user(diglen, &data->diglen);
	err |= put_user(diglen, &data32->diglen);
	err |= get_user(authkey, (compat_uptr_t *)&data->authkey);
	data32->authkey = 0;
	err |= put_user(authkey, &data32->authkey);
	err |= get_user(authklen, &data->authklen);
	err |= put_user(authklen, &data32->authklen);
	err |= get_user(alg, &data->alg);
	err |= put_user(alg, &data32->alg);

	return err;
}

static unsigned int convert_cmd(unsigned int cmd)
{
	switch (cmd) {
	case COMPAT_QCEDEV_IOCTL_ENC_REQ:
		return QCEDEV_IOCTL_ENC_REQ;
	case COMPAT_QCEDEV_IOCTL_DEC_REQ:
		return QCEDEV_IOCTL_DEC_REQ;
	case COMPAT_QCEDEV_IOCTL_SHA_INIT_REQ:
		return QCEDEV_IOCTL_SHA_INIT_REQ;
	case COMPAT_QCEDEV_IOCTL_SHA_UPDATE_REQ:
		return QCEDEV_IOCTL_SHA_UPDATE_REQ;
	case COMPAT_QCEDEV_IOCTL_SHA_FINAL_REQ:
		return QCEDEV_IOCTL_SHA_FINAL_REQ;
	case COMPAT_QCEDEV_IOCTL_GET_SHA_REQ:
		return QCEDEV_IOCTL_GET_SHA_REQ;
	case COMPAT_QCEDEV_IOCTL_LOCK_CE:
		return QCEDEV_IOCTL_LOCK_CE;
	case COMPAT_QCEDEV_IOCTL_UNLOCK_CE:
		return QCEDEV_IOCTL_UNLOCK_CE;
	case COMPAT_QCEDEV_IOCTL_GET_CMAC_REQ:
		return QCEDEV_IOCTL_GET_CMAC_REQ;
	case COMPAT_QCEDEV_IOCTL_UPDATE_FIPS_STATUS: 
		return QCEDEV_IOCTL_UPDATE_FIPS_STATUS;
	case COMPAT_QCEDEV_IOCTL_QUERY_FIPS_STATUS:
		return QCEDEV_IOCTL_QUERY_FIPS_STATUS;
	default:
		return cmd;
	}

}

long compat_qcedev_ioctl(struct file *file,
		unsigned int cmd, unsigned long arg)
{
	long ret;

	switch (cmd) {
	case COMPAT_QCEDEV_IOCTL_LOCK_CE:
	case COMPAT_QCEDEV_IOCTL_UNLOCK_CE: 
	case COMPAT_QCEDEV_IOCTL_QUERY_FIPS_STATUS: {
		pr_err("lock/unlock command\n");
		return qcedev_ioctl(file, convert_cmd(cmd), 0);
	}
	case COMPAT_QCEDEV_IOCTL_ENC_REQ:
	case COMPAT_QCEDEV_IOCTL_DEC_REQ: {
		struct compat_qcedev_cipher_op_req __user *data32;
		struct qcedev_cipher_op_req __user *data;
		int err;

		data32 = compat_ptr(arg);
		data = compat_alloc_user_space(sizeof(*data));
		if (!data)
			return -EFAULT;

		err = compat_get_qcedev_cipher_op_req(data32, data);
		if (err)
			return err;

		ret = qcedev_ioctl(file, convert_cmd(cmd), (unsigned long)data);
		err = compat_put_qcedev_cipher_op_req(data32, data);
		return ret ? ret : err;
	}
	case COMPAT_QCEDEV_IOCTL_SHA_INIT_REQ:
	case COMPAT_QCEDEV_IOCTL_SHA_UPDATE_REQ:
	case COMPAT_QCEDEV_IOCTL_SHA_FINAL_REQ:
	case COMPAT_QCEDEV_IOCTL_GET_CMAC_REQ:
	case COMPAT_QCEDEV_IOCTL_GET_SHA_REQ: {
		struct compat_qcedev_sha_op_req __user *data32;
		struct qcedev_sha_op_req __user *data;
		int err;

		data32 = compat_ptr(arg);
		data = compat_alloc_user_space(sizeof(*data));
		if (!data)
			return -EFAULT;

		err = compat_get_qcedev_sha_op_req(data32, data);
		if (err)
			return err;

		ret = qcedev_ioctl(file, convert_cmd(cmd), (unsigned long)data);
		err = compat_put_qcedev_sha_op_req(data32, data);
		return ret ? ret : err;
	}
	case COMPAT_QCEDEV_IOCTL_UPDATE_FIPS_STATUS: {
		unsigned int *pf_status32;
		unsigned int *pf_status;
		uint32_t val;
		int err;

		pf_status32 = compat_ptr(arg);
		pf_status = compat_alloc_user_space(sizeof(*pf_status));
		pr_err("FIPS command\n");

		err = get_user(val, pf_status32);
		if (err)
			return err;
		err = put_user(val, pf_status);
		if (err)
			return err;
		ret = qcedev_ioctl(file, convert_cmd(cmd), (unsigned long)pf_status);
		err = get_user(val, pf_status);
		if (err)
			return err;
		err = put_user(val, pf_status32);
		if (err)
			return err;
		pr_err("pf_status32 = %x\n", *pf_status32);
		return ret ? ret : err;
	}
	default:
		return -ENOIOCTLCMD;
	}
	return 0;
}
EXPORT_SYMBOL(compat_qcedev_ioctl);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("QTI 32-64 Compatibility for Crypto driver");
