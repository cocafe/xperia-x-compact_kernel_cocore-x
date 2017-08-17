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
#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <crypto/hash.h>
#include <crypto/ctr.h>
#include <crypto/des.h>
#include <crypto/aes.h>
#include <crypto/sha.h>
#include <crypto/hash.h>
#include <crypto/algapi.h>
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <crypto/scatterwalk.h>
#include <crypto/internal/hash.h>
#include <linux/platform_data/qcom_crypto_device.h>
#include <linux/qcrypto.h>

#include "../qcrypto_wrapper.h"
#include "qcryptoi.h"
#include "qcrypto_fips.h"

/*
 * Callback function
 */
static void _fips_cb(struct crypto_async_request *crypto_async_req, int err)
{
	struct _fips_completion *fips_completion = crypto_async_req->data;
	if (err == -EINPROGRESS)
		return;

	fips_completion->err = err;
	complete(&fips_completion->completion);
}

/*
 * Function to prefix if needed
 */
static int _fips_get_alg_cra_name(char cra_name[],
				char *prefix, unsigned int size)
{
	char new_cra_name[CRYPTO_MAX_ALG_NAME];
	strlcpy(new_cra_name, prefix, CRYPTO_MAX_ALG_NAME);
	if (CRYPTO_MAX_ALG_NAME < size + strlen(prefix))
		return -EINVAL;

	strlcat(new_cra_name, cra_name, CRYPTO_MAX_ALG_NAME);
	strlcpy(cra_name, new_cra_name, CRYPTO_MAX_ALG_NAME);
	return 0;
}

/*
 * Sha/HMAC self tests
 */
int _fips_qcrypto_sha_selftest(struct fips_selftest_data *selftest_d)
{
	int rc = 0, err, tv_index = 0, num_tv;
	char *k_out_buf = NULL;
	struct scatterlist fips_sg;
	struct crypto_ahash *tfm;
	struct ahash_request *ahash_req;
	struct _fips_completion fips_completion;
	struct _fips_test_vector_sha_hmac tv_sha_hmac;
	char *k_align_src = NULL;

	num_tv = (sizeof(fips_test_vector_sha_hmac)) /
	(sizeof(struct _fips_test_vector_sha_hmac));

	/* One-by-one testing */
	for (tv_index = 0; tv_index < num_tv; tv_index++) {
		memcpy(&tv_sha_hmac, &fips_test_vector_sha_hmac[tv_index],
			(sizeof(struct _fips_test_vector_sha_hmac)));
		k_out_buf = qcryptow_i_kzalloc(tv_sha_hmac.diglen, GFP_KERNEL);
		if (k_out_buf == NULL) {
			qcryptow_pr_err("qcrypto: Failed to allocate memory for k_out_buf %ld\n",
				qcryptow_i_PTR_ERR(k_out_buf));
			return -ENOMEM;
		}

		memset(k_out_buf, 0, tv_sha_hmac.diglen);

		/* Single buffer allocation for in place operation */
		/* if k_aligh_src is not used, 8974 crash */
		k_align_src = kzalloc(tv_sha_hmac.ilen, GFP_KERNEL);
		if (k_align_src == NULL) {
			pr_err("qcrypto:, Failed to allocate memory for k_align_src %ld\n",
			PTR_ERR(k_align_src));
			return -ENOMEM;
		}
		memcpy(k_align_src, tv_sha_hmac.input,
			tv_sha_hmac.ilen);

		init_completion(&fips_completion.completion);

		/* use_sw flags are set in dtsi file which makes
		default Linux API calls to go to s/w crypto instead
		of h/w crypto. This code makes sure that all selftests
		calls always go to h/w, independent of DTSI flags. */
		if (tv_sha_hmac.klen == 0) {
			if (selftest_d->prefix_ahash_algo)
				if (_fips_get_alg_cra_name(tv_sha_hmac
					.hash_alg, selftest_d->algo_prefix,
					strlen(tv_sha_hmac.hash_alg))) {
					rc = -1;
					qcryptow_pr_err("Algo Name is too long for tv %d\n",
					tv_index);
					goto clr_buf;
				}
		} else {
			if (selftest_d->prefix_hmac_algo)
				if (_fips_get_alg_cra_name(tv_sha_hmac
					.hash_alg, selftest_d->algo_prefix,
					strlen(tv_sha_hmac.hash_alg))) {
					rc = -1;
					qcryptow_pr_err("Algo Name is too long for tv %d\n",
					tv_index);
					goto clr_buf;
				}
		}

#ifdef FIPS_DEBUG
		qcryptow_pr_info("qfips:qcrypto: test %s\n", tv_sha_hmac.hash_alg);
#endif
		tfm = crypto_alloc_ahash(tv_sha_hmac.hash_alg, 0, 0);
		if (qcryptow_i_IS_ERR(tfm)) {
			pr_err("qcrypto: %s algorithm not found\n",
			tv_sha_hmac.hash_alg);
			rc = qcryptow_i_PTR_ERR(tfm);
			goto clr_buf;
		}

		ahash_req = ahash_request_alloc(tfm, GFP_KERNEL);
		if (!ahash_req) {
			qcryptow_pr_err("qcrypto: ahash_request_alloc failed\n");
			rc = -ENOMEM;
			goto clr_tfm;
		}
		rc = qcrypto_ahash_set_device(ahash_req, selftest_d->ce_device);
		if (rc != 0) {
			qcryptow_pr_err("%s qcrypto_cipher_set_device failed with err %d\n",
				__func__, rc);
			goto clr_ahash_req;
		}
		ahash_request_set_callback(ahash_req,
			CRYPTO_TFM_REQ_MAY_BACKLOG,
			_fips_cb, &fips_completion);

		sg_init_one(&fips_sg, k_align_src, tv_sha_hmac.ilen);

		crypto_ahash_clear_flags(tfm, ~0);
		if (tv_sha_hmac.klen != 0) {
			rc = crypto_ahash_setkey(tfm, tv_sha_hmac.key,
				tv_sha_hmac.klen);
			if (rc) {
				qcryptow_pr_err("qcrypto: crypto_ahash_setkey failed\n");
				goto clr_ahash_req;
			}
		}

		ahash_request_set_crypt(ahash_req, &fips_sg, k_out_buf,
			tv_sha_hmac.ilen);
		rc = crypto_ahash_digest(ahash_req);
		if (rc == -EINPROGRESS || rc == -EBUSY) {
			rc = wait_for_completion_interruptible(
				&fips_completion.completion);
			err = fips_completion.err;
			if (!rc && !err) {
				INIT_COMPLETION(fips_completion.completion);
			} else {
				qcryptow_pr_err("qcrypto:SHA: wait_for_completion failed\n");
				goto clr_ahash_req;
			}

		}

		if (memcmp(k_out_buf, tv_sha_hmac.digest,
			tv_sha_hmac.diglen)) {
			qcryptow_pr_err("qcrypto: KAT failed for %s\n", tv_sha_hmac.hash_alg);
			rc = -1;
		}

clr_ahash_req:
		ahash_request_free(ahash_req);
clr_tfm:
		crypto_free_ahash(tfm);
clr_buf:
		qcryptow_kzfree(k_out_buf);
		qcryptow_kzfree(k_align_src);

	/* For any failure, return error */
		if (rc)
			return rc;

	}
	return rc;
}

/*
* Cipher algorithm self tests
*/
int _fips_qcrypto_cipher_selftest(struct fips_selftest_data *selftest_d)
{
	int rc = 0, err, tv_index, num_tv;
	struct crypto_ablkcipher *tfm;
	struct ablkcipher_request *ablkcipher_req;
	struct _fips_completion fips_completion;
	char *k_align_src = NULL;
	struct scatterlist fips_sg;
	struct _fips_test_vector_cipher tv_cipher;

	num_tv = (sizeof(fips_test_vector_cipher)) /
		(sizeof(struct _fips_test_vector_cipher));

	/* One-by-one testing */
	for (tv_index = 0; tv_index < num_tv; tv_index++) {

		memcpy(&tv_cipher, &fips_test_vector_cipher[tv_index],
			(sizeof(struct _fips_test_vector_cipher)));

		/* Single buffer allocation for in place operation */
		k_align_src = qcryptow_i_kzalloc(tv_cipher.pln_txt_len, GFP_KERNEL);
		if (k_align_src == NULL) {
			qcryptow_pr_err("qcrypto:, Failed to allocate memory for k_align_src %ld\n",
			qcryptow_i_PTR_ERR(k_align_src));
			return -ENOMEM;
		}

		memcpy(&k_align_src[0], tv_cipher.pln_txt,
			tv_cipher.pln_txt_len);

		/* use_sw flags are set in dtsi file which makes
		default Linux API calls to go to s/w crypto instead
		of h/w crypto. This code makes sure that all selftests
		calls always go to h/w, independent of DTSI flags. */
		if (!strcmp(tv_cipher.mod_alg, "xts(aes)")) {
			if (selftest_d->prefix_aes_xts_algo)
				if (_fips_get_alg_cra_name(
					tv_cipher.mod_alg,
					selftest_d->algo_prefix,
					strlen(tv_cipher.mod_alg))) {
					rc = -1;
					qcryptow_pr_err("Algo Name is too long for tv %d\n",
					tv_index);
					goto clr_buf;
				}
		} else {
			if (selftest_d->prefix_aes_cbc_ecb_ctr_algo)
				if (_fips_get_alg_cra_name(
					tv_cipher.mod_alg,
					selftest_d->algo_prefix,
					strlen(tv_cipher.mod_alg))) {
					rc = -1;
					qcryptow_pr_err("Algo Name is too long for tv %d\n",
					tv_index);
					goto clr_buf;
				}
		}

#ifdef FIPS_DEBUG
		qcryptow_pr_info("qfips:qcrypto: cipher algorithm %s\n", tv_cipher.mod_alg);
#endif
		tfm = crypto_alloc_ablkcipher(tv_cipher.mod_alg, 0, 0);
		if (qcryptow_i_IS_ERR(tfm)) {
			qcryptow_pr_err("qcrypto: %s algorithm not found\n",
			tv_cipher.mod_alg);
			rc = -ENOMEM;
			goto clr_buf;
		}

		ablkcipher_req = ablkcipher_request_alloc(tfm, GFP_KERNEL);
		if (!ablkcipher_req) {
			qcryptow_pr_err("qcrypto: ablkcipher_request_alloc failed\n");
			rc = -ENOMEM;
			goto clr_tfm;
		}
		rc = qcrypto_cipher_set_device(ablkcipher_req,
			selftest_d->ce_device);
		if (rc != 0) {
			qcryptow_pr_err("%s qcrypto_cipher_set_device failed with err %d\n",
				__func__, rc);
			goto clr_ablkcipher_req;
		}
		ablkcipher_request_set_callback(ablkcipher_req,
			CRYPTO_TFM_REQ_MAY_BACKLOG,
			_fips_cb, &fips_completion);

		crypto_ablkcipher_clear_flags(tfm, ~0);
		rc = crypto_ablkcipher_setkey(tfm, tv_cipher.key,
			tv_cipher.klen);
		if (rc) {
			qcryptow_pr_err("qcrypto: crypto_ablkcipher_setkey failed\n");
			goto clr_ablkcipher_req;
		}
		sg_set_buf(&fips_sg, k_align_src, tv_cipher.enc_txt_len);
		sg_mark_end(&fips_sg);
		ablkcipher_request_set_crypt(ablkcipher_req,
			&fips_sg, &fips_sg, tv_cipher.pln_txt_len,
			tv_cipher.iv);

		/**** Encryption Test ****/
		init_completion(&fips_completion.completion);
		rc = crypto_ablkcipher_encrypt(ablkcipher_req);
		if (rc == -EINPROGRESS || rc == -EBUSY) {
			rc = wait_for_completion_interruptible(
				&fips_completion.completion);
			err = fips_completion.err;
			if (!rc && !err) {
				INIT_COMPLETION(fips_completion.completion);
			} else {
				qcryptow_pr_err("qcrypto:cipher:ENC, wait_for_completion failed\n");
				goto clr_ablkcipher_req;
			}

		}

		if (memcmp(k_align_src, tv_cipher.enc_txt,
			tv_cipher.enc_txt_len)) {
			rc = -1;
			qcryptow_pr_err("qcrypto:cipher:KAT failed for %s enc\n", tv_cipher.mod_alg);
			goto clr_ablkcipher_req;
		}

		/**** Decryption test ****/
		init_completion(&fips_completion.completion);
		rc = crypto_ablkcipher_decrypt(ablkcipher_req);
		if (rc == -EINPROGRESS || rc == -EBUSY) {
			rc = wait_for_completion_interruptible(
				&fips_completion.completion);
			err = fips_completion.err;
			if (!rc && !err) {
				INIT_COMPLETION(fips_completion.completion);
			} else {
				qcryptow_pr_err("qcrypto:cipher:DEC, wait_for_completion failed\n");
				goto clr_ablkcipher_req;
			}

		}

		if (memcmp(k_align_src, tv_cipher.pln_txt,
			tv_cipher.pln_txt_len)) {
			qcryptow_pr_err("qcrypto:cipher:KAT failed for %s dec\n", tv_cipher.mod_alg);
			rc = -1;
		}

clr_ablkcipher_req:
		ablkcipher_request_free(ablkcipher_req);
clr_tfm:
		crypto_free_ablkcipher(tfm);
clr_buf:
		qcryptow_kzfree(k_align_src);

		if (rc)
			return rc;

	}
	return rc;
}

/*
 * AEAD algorithm self tests
 */
int _fips_qcrypto_aead_selftest(struct fips_selftest_data *selftest_d)
{
	int rc = 0, err, tv_index, num_tv, authsize, buf_length;
	struct crypto_aead *tfm;
	struct aead_request *aead_req;
	struct _fips_completion fips_completion;
	struct scatterlist fips_sg, fips_assoc_sg;
	char *k_align_src = NULL;
	struct _fips_test_vector_aead tv_aead;

	num_tv = (sizeof(fips_test_vector_aead)) /
		(sizeof(struct _fips_test_vector_aead));

	/* One-by-one testing */
	for (tv_index = 0; tv_index < num_tv; tv_index++) {

		memcpy(&tv_aead, &fips_test_vector_aead[tv_index],
			(sizeof(struct _fips_test_vector_aead)));

		if (tv_aead.pln_txt_len > tv_aead.enc_txt_len)
			buf_length = tv_aead.pln_txt_len;
		else
			buf_length = tv_aead.enc_txt_len;

		authsize = abs(tv_aead.enc_txt_len - tv_aead.pln_txt_len);

		/* Single buffer allocation for in place operation */
		k_align_src = qcryptow_i_kzalloc(buf_length + authsize, GFP_KERNEL);
		if (k_align_src == NULL) {
			qcryptow_pr_err("qcrypto:, Failed to allocate memory for k_align_src %ld\n",
				qcryptow_i_PTR_ERR(k_align_src));
			return -ENOMEM;
		}
		memcpy(&k_align_src[0], tv_aead.pln_txt,
			tv_aead.pln_txt_len);

		/* use_sw flags are set in dtsi file which makes
		default Linux API calls to go to s/w crypto instead
		of h/w crypto. This code makes sure that all selftests
		calls always go to h/w, independent of DTSI flags. */
		if (selftest_d->prefix_aead_algo) {
			if (_fips_get_alg_cra_name(tv_aead.mod_alg,
				selftest_d->algo_prefix,
				strlen(tv_aead.mod_alg))) {
				rc = -1;
				qcryptow_pr_err("Algo Name is too long for tv %d\n",
					tv_index);
				goto clr_buf;
			}
		}
#ifdef FIPS_DEBUG
		qcryptow_pr_info("qfips: aead alg name %s\n", tv_aead.mod_alg);
#endif
		tfm = crypto_alloc_aead(tv_aead.mod_alg, 0, 0);
		if (qcryptow_i_IS_ERR(tfm)) {
			qcryptow_pr_err("qcrypto: %s algorithm not found\n",
				tv_aead.mod_alg);
			rc = -ENOMEM;
			goto clr_buf;
		}
		aead_req = aead_request_alloc(tfm, GFP_KERNEL);
		if (!aead_req) {
			qcryptow_pr_err("qcrypto:aead_request_alloc failed\n");
			rc = -ENOMEM;
			goto clr_tfm;
		}
		rc = qcrypto_aead_set_device(aead_req, selftest_d->ce_device);
		if (rc != 0) {
			qcryptow_pr_err("%s qcrypto_cipher_set_device failed with err %d\n",
				__func__, rc);
			goto clr_aead_req;
		}
		init_completion(&fips_completion.completion);
		aead_request_set_callback(aead_req,
			CRYPTO_TFM_REQ_MAY_BACKLOG,
			_fips_cb, &fips_completion);
		crypto_aead_clear_flags(tfm, ~0);
		rc = crypto_aead_setkey(tfm, tv_aead.key, tv_aead.klen);
		if (rc) {
			qcryptow_pr_err("qcrypto:crypto_aead_setkey failed\n");
			goto clr_aead_req;
		}
		rc = crypto_aead_setauthsize(tfm, authsize);
		if (rc) {
			qcryptow_pr_err("qcrypto:crypto_aead_setauthsize failed\n");
			goto clr_aead_req;
		}
		sg_init_one(&fips_sg, k_align_src,
		tv_aead.pln_txt_len + authsize);
		aead_request_set_crypt(aead_req, &fips_sg, &fips_sg,
			tv_aead.pln_txt_len , tv_aead.iv);
		sg_init_one(&fips_assoc_sg, tv_aead.assoc, tv_aead.alen);
		aead_request_set_assoc(aead_req, &fips_assoc_sg, tv_aead.alen);
		/**** Encryption test ****/
		rc = crypto_aead_encrypt(aead_req);
		if (rc == -EINPROGRESS || rc == -EBUSY) {
			rc = wait_for_completion_interruptible(
				&fips_completion.completion);
			err = fips_completion.err;
			if (!rc && !err) {
				INIT_COMPLETION(fips_completion.completion);
			} else {
				qcryptow_pr_err("qcrypto:aead:ENC, wait_for_completion failed\n");
				goto clr_aead_req;
			}

		}
		if (memcmp(k_align_src, tv_aead.enc_txt, tv_aead.enc_txt_len)) {
			rc = -1;
			qcryptow_pr_err("qcrypto:aead:KAT failed for %s enc", tv_aead.mod_alg);
			goto clr_aead_req;
		}

		/** Decryption test **/
		init_completion(&fips_completion.completion);
		aead_request_set_callback(aead_req,
			CRYPTO_TFM_REQ_MAY_BACKLOG,
			_fips_cb, &fips_completion);
		crypto_aead_clear_flags(tfm, ~0);
		rc = crypto_aead_setkey(tfm, tv_aead.key, tv_aead.klen);
		if (rc) {
			qcryptow_pr_err("qcrypto:aead:DEC, crypto_aead_setkey failed\n");
			goto clr_aead_req;
		}

		rc = crypto_aead_setauthsize(tfm, authsize);
		if (rc) {
			qcryptow_pr_err("qcrypto:aead:DEC, crypto_aead_setauthsize failed\n");
			goto clr_aead_req;
		}

		sg_init_one(&fips_sg, k_align_src,
			tv_aead.enc_txt_len + authsize);
		aead_request_set_crypt(aead_req, &fips_sg, &fips_sg,
			tv_aead.enc_txt_len, tv_aead.iv);
		sg_init_one(&fips_assoc_sg, tv_aead.assoc, tv_aead.alen);
		aead_request_set_assoc(aead_req, &fips_assoc_sg,
			tv_aead.alen);
		rc = crypto_aead_decrypt(aead_req);
		if (rc == -EINPROGRESS || rc == -EBUSY) {
			rc = wait_for_completion_interruptible(
				&fips_completion.completion);
			err = fips_completion.err;
			if (!rc && !err) {
				INIT_COMPLETION(fips_completion.completion);
			} else {
				qcryptow_pr_err("qcrypto:aead:DEC, wait_for_completion failed\n");
				goto clr_aead_req;
			}

		}

		if (memcmp(k_align_src, tv_aead.pln_txt, tv_aead.pln_txt_len)) {
			rc = -1;
			qcryptow_pr_err("qcrypto:aead:KAT failed for %s dec", tv_aead.mod_alg);
			goto clr_aead_req;
		}
clr_aead_req:
		aead_request_free(aead_req);
clr_tfm:
		crypto_free_aead(tfm);
clr_buf:
		qcryptow_kzfree(k_align_src);
	/* In case of any failure, return error */
		if (rc)
			return rc;
	}
	return rc;
}

