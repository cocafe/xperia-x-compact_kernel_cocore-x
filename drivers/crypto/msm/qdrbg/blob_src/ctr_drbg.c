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
#include "../msm_rng_wrapper.h"
#include "ctr_drbg.h"
#include "fips_drbg.h"

#define E_FAILURE 0Xffff
#define E_SUCCESS 0

#define AES128_KEY_SIZE   (16)
#define AES128_BLOCK_SIZE (16)

#define AES_TEXT_LENGTH (64)
#define MAX_TEXT_LENGTH (2048)

uint8_t df_initial_k[16] = "\x0\x1\x2\x3\x4\x5\x6\x7\x8\x9\xa\xb\xc\xd\xe\xf";

static void _crypto_cipher_test_complete(struct crypto_async_request *req,
				int err)
{
	struct msm_ctr_tcrypt_result_s *res = NULL;

	if (!req)
		return;

	res = req->data;
	if (!res)
		return;

	if (err == -EINPROGRESS)
		return;
	res->err = err;
	qdrbg_complete(&res->completion);
}

static int ctr_aes_init(struct ctr_drbg_ctx_s *ctx)
{
	int status = 0;

	ctx->aes_ctx.tfm = qdrbg_crypto_alloc_ablkcipher("qcrypto-ecb-aes", 0, 0);
	if (qdrbg_i_IS_ERR(ctx->aes_ctx.tfm) || (NULL == ctx->aes_ctx.tfm)) {
		qdrbg_m_pr_err("ctr_aes_init: qcom-ecb(aes) failed\n");
		status = -E_FAILURE;
		goto out;
	}

	ctx->aes_ctx.req = qdrbg_i_ablkcipher_request_alloc(ctx->aes_ctx.tfm,
							GFP_KERNEL);
	if (qdrbg_i_IS_ERR(ctx->aes_ctx.req) || (NULL == ctx->aes_ctx.req)) {
		qdrbg_m_pr_err("ctr_aes_init: Failed to allocate request.\n");
		status = -E_FAILURE;
		goto clr_tfm;
	}

	qdrbg_i_ablkcipher_request_set_callback(ctx->aes_ctx.req,
				CRYPTO_TFM_REQ_MAY_BACKLOG,
				_crypto_cipher_test_complete,
				&ctx->aes_ctx.result);

	qdrbg_memset(&ctx->aes_ctx.input, 0, sizeof(struct msm_ctr_buffer_s));
	qdrbg_memset(&ctx->aes_ctx.output, 0, sizeof(struct msm_ctr_buffer_s));

	/* Allocate memory. */
	ctx->aes_ctx.input.virt_addr  = qdrbg_i_kmalloc(AES128_BLOCK_SIZE,
						GFP_KERNEL | __GFP_DMA);
	if (NULL == ctx->aes_ctx.input.virt_addr) {
		qdrbg_m_pr_err("%s: Failed to allocate input.virt_addr.\n",
				__func__);
		status = -E_FAILURE;
		goto clr_req;
	}
	ctx->aes_ctx.output.virt_addr = qdrbg_i_kmalloc(AES128_BLOCK_SIZE,
						GFP_KERNEL | __GFP_DMA);
	if (NULL == ctx->aes_ctx.output.virt_addr) {
		qdrbg_m_pr_err("%s: Failed to allocate output.virt_addr.\n",
				__func__);
		status = -E_FAILURE;
		goto clr_input;
	}

	/*--------------------------------------------------------------------
	Set DF AES mode
	----------------------------------------------------------------------*/
	ctx->df_aes_ctx.tfm = qdrbg_crypto_alloc_ablkcipher("qcrypto-ecb-aes",
								0,
								0);
	if ((NULL == ctx->df_aes_ctx.tfm) ||
		qdrbg_i_IS_ERR(ctx->df_aes_ctx.tfm)) {
		qdrbg_m_pr_err("ctr_aes_init: qcrypto-ecb-aes failed\n");
		status = -E_FAILURE;
		goto clr_output;
	}

	ctx->df_aes_ctx.req = qdrbg_i_ablkcipher_request_alloc(
							ctx->df_aes_ctx.tfm,
							GFP_KERNEL);
	if (qdrbg_i_IS_ERR(ctx->df_aes_ctx.req) ||
		(NULL == ctx->df_aes_ctx.req)) {
		qdrbg_m_pr_err("%s: Failed to allocate df_aes_ctx.req\n",
				__func__);
		status = -E_FAILURE;
		goto clr_df_tfm;
	}

	qdrbg_i_ablkcipher_request_set_callback(ctx->df_aes_ctx.req,
				CRYPTO_TFM_REQ_MAY_BACKLOG,
				_crypto_cipher_test_complete,
				&ctx->df_aes_ctx.result);

	qdrbg_memset(&ctx->df_aes_ctx.input,
			0,
			sizeof(struct msm_ctr_buffer_s));
	qdrbg_memset(&ctx->df_aes_ctx.output,
			0,
			sizeof(struct msm_ctr_buffer_s));

	ctx->df_aes_ctx.input.virt_addr  = qdrbg_i_kmalloc(AES128_BLOCK_SIZE,
						GFP_KERNEL | __GFP_DMA);
	if (NULL == ctx->df_aes_ctx.input.virt_addr) {
		qdrbg_m_pr_err("%s: Failed to allocate df_aes_ctx.input.virt_addr\n",
				__func__);
		status = -E_FAILURE;
		goto clr_df_req;
	}

	ctx->df_aes_ctx.output.virt_addr = qdrbg_i_kmalloc(AES128_BLOCK_SIZE,
						GFP_KERNEL | __GFP_DMA);
	if (NULL == ctx->df_aes_ctx.output.virt_addr) {
		qdrbg_m_pr_err("%s: Failed to allocate df_aes_ctx.output.virt_addr\n",
				__func__);
		status = -E_FAILURE;
		goto clr_df_input;
	}

	goto out;

clr_df_input:
	if (ctx->df_aes_ctx.input.virt_addr) {
		qdrbg_kzfree(ctx->df_aes_ctx.input.virt_addr);
		ctx->df_aes_ctx.input.virt_addr = NULL;
	}
clr_df_req:
	if (ctx->df_aes_ctx.req) {
		qdrbg_i_ablkcipher_request_free(ctx->df_aes_ctx.req);
		ctx->df_aes_ctx.req = NULL;
	}
clr_df_tfm:
	if (ctx->df_aes_ctx.tfm) {
			qdrbg_i_crypto_free_ablkcipher(ctx->df_aes_ctx.tfm);
			ctx->df_aes_ctx.tfm = NULL;
		}
clr_output:
	if (ctx->aes_ctx.output.virt_addr) {
		qdrbg_kzfree(ctx->aes_ctx.output.virt_addr);
		ctx->aes_ctx.output.virt_addr = NULL;
	}
clr_input:
	if (ctx->aes_ctx.input.virt_addr) {
		qdrbg_kzfree(ctx->aes_ctx.input.virt_addr);
		ctx->aes_ctx.input.virt_addr = NULL;
	}
clr_req:
	if (ctx->aes_ctx.req) {
		qdrbg_i_ablkcipher_request_free(ctx->aes_ctx.req);
		ctx->aes_ctx.req = NULL;
	}
clr_tfm:
	if (ctx->aes_ctx.tfm) {
		qdrbg_i_crypto_free_ablkcipher(ctx->aes_ctx.tfm);
		ctx->aes_ctx.tfm = NULL;
	}
out:
	return status;
}

/*
 * Increments the V field in *ctx
 */
static void increment_V(struct ctr_drbg_ctx_s *ctx)
{
	uint8_t *p = &ctx->seed.key_V.V[0];

	qdrbg_crypto_inc(p, 16);

	return;
}

/*
 * The NIST update function.  It updates the key and V to new values
 * (to prevent backtracking) and optionally stirs in data.  data may
 * be null, otherwise *data is from 0 to 256 bits long.
 * keysched is an optional keyschedule to use as an optimization.  It
 * must be consistent with the key in *ctx.  No changes are made to
 * *ctx until it is assured that there will be no failures.  Note that
 * data_len is in bytes.  (That may not be offical NIST
 * recommendation, but I do it anyway; they say "or equivalent" and
 * this is equivalent enough.)
 */
static enum ctr_drbg_status_t
update(struct ctr_drbg_ctx_s *ctx, const uint8_t *data, size_t data_len)
{
	uint8_t temp[32];
	unsigned int i;
	int rc;
	struct scatterlist sg_in, sg_out;

	for (i = 0; i < 2; ++i) {
		increment_V(ctx);
		qdrbg_i_init_completion(&ctx->aes_ctx.result.completion);

		/*
		 * Note: personalize these called routines for
		 * specific testing.
		 */
		qdrbg_memcpy(ctx->aes_ctx.input.virt_addr,
			ctx->seed.key_V.V,
			CTR_DRBG_BLOCK_LEN_BYTES);

		qdrbg_i_crypto_ablkcipher_clear_flags(ctx->aes_ctx.tfm, ~0);

		/* Encrypt some clear text! */

		qdrbg_sg_init_one(&sg_in,
			ctx->aes_ctx.input.virt_addr,
			AES128_BLOCK_SIZE);
		qdrbg_sg_init_one(&sg_out,
			ctx->aes_ctx.output.virt_addr,
			AES128_BLOCK_SIZE);
		qdrbg_i_ablkcipher_request_set_crypt(ctx->aes_ctx.req,
						&sg_in,
						&sg_out,
						CTR_DRBG_BLOCK_LEN_BYTES,
						NULL);

		rc = qdrbg_i_crypto_ablkcipher_encrypt(ctx->aes_ctx.req);

		switch (rc) {
		case 0:
			break;
		case -EINPROGRESS:
		case -EBUSY:
			rc = qdrbg_wait_for_completion_interruptible(
				&ctx->aes_ctx.result.completion);
			if (!rc && !ctx->aes_ctx.result.err) {
				qdrbg_m_INIT_COMPLETION(
					ctx->aes_ctx.result.completion);
				break;
			}
		/* fall through */
		default:
			break;
		}

		qdrbg_i_init_completion(&ctx->aes_ctx.result.completion);

		qdrbg_memcpy(temp + AES128_BLOCK_SIZE * i,
			ctx->aes_ctx.output.virt_addr,
			AES128_BLOCK_SIZE);
	}

	for (i = 0; i < data_len; ++i)
		ctx->seed.as_bytes[i] = temp[i] ^ data[i];

	/* now copy the rest of temp to key and V */
	if (32 > data_len) {
		qdrbg_memcpy(ctx->seed.as_bytes + data_len,
			temp + data_len,
			32 - data_len);
	}

	qdrbg_memset(temp, 0, 32);
	return CTR_DRBG_SUCCESS;
}

/*
 * Reseeds the CTR_DRBG instance with entropy.  entropy_len_bits must
 * be exactly 256.
 */
enum ctr_drbg_status_t ctr_drbg_reseed(struct ctr_drbg_ctx_s *ctx,
					const void     *entropy,
					size_t         entropy_len_bits)
{
	enum ctr_drbg_status_t update_rv;
	uint8_t           seed_material[32];
	int               rc;

	if (ctx == NULL || entropy == NULL) {
		qdrbg_m_pr_err("%s: invalid argument: ctx=%p, entropy=%p\n",
				__func__, ctx, entropy);
		return CTR_DRBG_INVALID_ARG;
	}

	update_rv = block_cipher_df(ctx,
				(uint8_t *)entropy,
				(entropy_len_bits / 8),
				seed_material,
				32
				);
	if (CTR_DRBG_SUCCESS != update_rv) {
		qdrbg_memset(seed_material, 0, 32);
		qdrbg_m_pr_err("%s: block_cipher_df err: %d\n",
				__func__, update_rv);
		return CTR_DRBG_GENERAL_ERROR;
	}

	rc = qdrbg_i_crypto_ablkcipher_setkey(ctx->aes_ctx.tfm,
				ctx->seed.key_V.key,
				AES128_KEY_SIZE
				);
	if (rc) {
		qdrbg_memset(seed_material, 0, 32);
		qdrbg_m_pr_err("%s: crypto_ablkcipher_setkey err: %d\n",
				__func__, rc);
		return CTR_DRBG_GENERAL_ERROR;
	}

	update_rv = update(ctx, (const uint8_t *)seed_material, 32);
	if (update_rv != CTR_DRBG_SUCCESS) {
		qdrbg_memset(seed_material, 0, 32);
		qdrbg_m_pr_err("%s: update seed err: %d\n",
				__func__, update_rv);
		return update_rv;
	}
	ctx->reseed_counter = 1;  /* think 0 but SP 800-90 says 1 */

	qdrbg_memset(seed_material, 0, 32);

	return CTR_DRBG_SUCCESS;

}

/*
 * The NIST instantiate function.  entropy_len_bits must be exactly
 * 256.  After reseed_interval generate requests, generated requests
 * will fail  until the CTR_DRBG instance is reseeded. As per NIST SP
 * 800-90, an error is returned if reseed_interval > 2^48.
 */

enum ctr_drbg_status_t
ctr_drbg_instantiate(struct ctr_drbg_ctx_s *ctx,
			const uint8_t *entropy,
			size_t entropy_len_bits,
			const uint8_t *nonce,
			size_t nonce_len_bits,
			unsigned long long reseed_interval)
{

	enum ctr_drbg_status_t update_rv;
	uint8_t           seed_material[32];
	uint8_t           df_input[32];
	int               rc;

	if (ctx == NULL || entropy == NULL || nonce == NULL) {
		qdrbg_m_pr_debug("%s: invalid arg: ctx=%p, entropy=%x, n=%x\n",
				__func__, ctx, entropy, nonce);
		return CTR_DRBG_INVALID_ARG;
	}
	if (((nonce_len_bits / 8) + (entropy_len_bits / 8)) > 32) {
		qdrbg_m_pr_debug(
			"\nentropy_len_bits + nonce_len_bits is too long!\n");
		return CTR_DRBG_INVALID_NONCE_ENTROPY;
	}

	if (reseed_interval > (1ULL << 48)) {
		qdrbg_m_pr_err("%s: invalid reseed_interval=%llx\n",
				__func__, reseed_interval);
		return CTR_DRBG_INVALID_SEED_INTERVAL;
	}

	rc = ctr_aes_init(ctx);
	if (rc){
		qdrbg_m_pr_err("%s: ctr_aes_init err=%d\n",
				__func__, rc);
		return CTR_DRBG_GENERAL_ERROR;
	}

	qdrbg_memset(ctx->seed.as_bytes, 0, sizeof(ctx->seed.as_bytes));
	qdrbg_memcpy(df_input, (uint8_t *)entropy, entropy_len_bits / 8);
	qdrbg_memcpy(df_input + (entropy_len_bits / 8),
			nonce,
			nonce_len_bits / 8);

	update_rv = block_cipher_df(ctx, df_input, 24, seed_material, 32);
	qdrbg_memset(df_input, 0, 32);

	if (CTR_DRBG_SUCCESS != update_rv) {
		qdrbg_memset(seed_material, 0, 32);
		qdrbg_m_pr_err("%s: block_cipher_df err=%d\n",
				__func__, update_rv);
		return CTR_DRBG_GENERAL_ERROR;
	}

	rc = qdrbg_i_crypto_ablkcipher_setkey(ctx->aes_ctx.tfm,
				ctx->seed.key_V.key,
				AES128_KEY_SIZE);
	if (rc) {
		qdrbg_memset(seed_material, 0, 32);
		qdrbg_m_pr_err("%s: crypto_ablkcipher_setkey err=%d\n",
				__func__, rc);
		return CTR_DRBG_GENERAL_ERROR;
	}
	update_rv = update(ctx, (const uint8_t *)seed_material, 32);
	if (update_rv != CTR_DRBG_SUCCESS) {
		qdrbg_memset(seed_material, 0, 32);
		qdrbg_m_pr_err("%s: update seed err=%d\n",
				__func__, update_rv);
		return update_rv;
	}

	ctx->reseed_counter = 1;  /* think 0 but SP 800-90 says 1 */
	ctx->reseed_interval = reseed_interval;

	qdrbg_memset(seed_material, 0, 32);


	return CTR_DRBG_SUCCESS;
}

/*
 * Generate random bits. len_bits is specified in bits, as required by
 * NIST SP800-90.  It fails with CTR_DRBG_NEEDS_RESEED if the number
 * of generates since instantiation or the last reseed >= the
 * reseed_interval supplied at instantiation.  len_bits must be a
 * multiple of 8.  len_bits must not exceed 2^19, as per NIST SP
 * 800-90. Optionally stirs in additional_input which is
 * additional_input_len_bits long, and is silently rounded up to a
 * multiple of 8.  CTR_DRBG_INVALID_ARG is returned if any pointer arg
 * is null and the corresponding length is non-zero or if
 * additioanl_input_len_bits > 256.
 */
enum ctr_drbg_status_t
ctr_drbg_generate_w_data(struct ctr_drbg_ctx_s *ctx,
			void   *additional_input,
			size_t additional_input_len_bits,
			void   *buffer,
			size_t len_bits)
{
	size_t total_blocks = (len_bits + 127) / 128;
	enum ctr_drbg_status_t update_rv;
	int rv = 0;
	size_t i;
	int rc;
	struct scatterlist sg_in, sg_out;

	if (ctx == NULL) {
		qdrbg_m_pr_err("%s: ctx is null\n", __func__);
		return CTR_DRBG_INVALID_ARG;
	}
	if (buffer == NULL && len_bits > 0) {
		qdrbg_m_pr_debug("%s: buffer is null\n", __func__);
		return CTR_DRBG_INVALID_ARG;
	}
	if (len_bits % 8 != 0) {
		qdrbg_m_pr_debug("%s: len_bits not multiple of 8\n", __func__);
		return CTR_DRBG_INVALID_ARG;
	}
	if (len_bits > (1<<19)) {
		qdrbg_m_pr_debug("%s: len_bits exceed 2^19\n", __func__);
		return CTR_DRBG_INVALID_ARG;
	}

	if ((additional_input == NULL && additional_input_len_bits > 0) ||
		additional_input_len_bits > CTR_DRBG_SEED_LEN_BITS) {
		qdrbg_m_pr_err("%s: additional input invalid arg\n", __func__);
		return CTR_DRBG_INVALID_ARG;
	}
	if (ctx->reseed_counter > ctx->reseed_interval)
		return CTR_DRBG_NEEDS_RESEED;

	rc = qdrbg_i_crypto_ablkcipher_setkey(ctx->aes_ctx.tfm,
				ctx->seed.key_V.key,
				AES128_KEY_SIZE);
	if (rc != 0) {
		qdrbg_m_pr_err("%s: crypto_ablkcipher_setkey err=%d\n",
				__func__, rc);
		return CTR_DRBG_GENERAL_ERROR;
	}

	if (!ctx->continuous_test_started) {
		increment_V(ctx);
		qdrbg_i_init_completion(&ctx->aes_ctx.result.completion);
		qdrbg_i_crypto_ablkcipher_clear_flags(ctx->aes_ctx.tfm, ~0);
		qdrbg_memcpy(ctx->aes_ctx.input.virt_addr,
				ctx->seed.key_V.V,
				16);
		qdrbg_sg_init_one(&sg_in, ctx->aes_ctx.input.virt_addr, 16);
		qdrbg_sg_init_one(&sg_out, ctx->aes_ctx.output.virt_addr, 16);
		qdrbg_i_ablkcipher_request_set_crypt(ctx->aes_ctx.req,
					&sg_in,
					&sg_out,
					CTR_DRBG_BLOCK_LEN_BYTES, NULL);
		rc = qdrbg_i_crypto_ablkcipher_encrypt(ctx->aes_ctx.req);
		switch (rc) {
		case 0:
			break;
		case -EINPROGRESS:
		case -EBUSY:
			rc = qdrbg_wait_for_completion_interruptible(
				&ctx->aes_ctx.result.completion);
			if (!rc && !ctx->aes_ctx.result.err) {
				qdrbg_m_INIT_COMPLETION(
					ctx->aes_ctx.result.completion);
				break;
			}
			/* fall through */
		default:
			break;
		}
		qdrbg_i_init_completion(&ctx->aes_ctx.result.completion);

		qdrbg_memcpy(ctx->prev_drn, ctx->aes_ctx.output.virt_addr, 16);
		ctx->continuous_test_started = 1;
	}

	/* Generate the output */
	for (i = 0; i < total_blocks; ++i) {
		/* Increment the counter */
		increment_V(ctx);
		if (((len_bits % 128) != 0) && (i == (total_blocks - 1))) {
			/* last block and it's a fragment */
			qdrbg_i_init_completion(
				&ctx->aes_ctx.result.completion);

			/*
			 * Note: personalize these called routines for
			 * specific testing.
			 */

			qdrbg_i_crypto_ablkcipher_clear_flags(ctx->aes_ctx.tfm,
								~0);

			/* Encrypt some clear text! */

			qdrbg_memcpy(ctx->aes_ctx.input.virt_addr,
				ctx->seed.key_V.V,
				16);
			qdrbg_sg_init_one(&sg_in,
				ctx->aes_ctx.input.virt_addr,
				16);
			qdrbg_sg_init_one(&sg_out,
				ctx->aes_ctx.output.virt_addr,
				16);
			qdrbg_i_ablkcipher_request_set_crypt(ctx->aes_ctx.req,
				&sg_in,
				&sg_out,
				CTR_DRBG_BLOCK_LEN_BYTES,
				NULL);

			rc = qdrbg_i_crypto_ablkcipher_encrypt(
				ctx->aes_ctx.req);

			switch (rc) {
			case 0:
				break;
			case -EINPROGRESS:
			case -EBUSY:
				rc = qdrbg_wait_for_completion_interruptible(
					&ctx->aes_ctx.result.completion);
				if (!rc && !ctx->aes_ctx.result.err) {
					qdrbg_m_INIT_COMPLETION(
						ctx->aes_ctx.result.completion);
					break;
				}
				/* fall through */
			default:
				break;
			}

			qdrbg_i_init_completion(&ctx->aes_ctx.result.completion);

			if (!qdrbg_memcmp(ctx->prev_drn,
					ctx->aes_ctx.output.virt_addr,
					16)) {
				qdrbg_panic("%s: FIPS DRBG continuous test failed!\n",
					__func__);
			}
			else
				qdrbg_memcpy(ctx->prev_drn,
					ctx->aes_ctx.output.virt_addr,
					16);
			rv = 0;
			qdrbg_memcpy((uint8_t *)buffer + 16*i,
				ctx->aes_ctx.output.virt_addr,
				(len_bits % 128)/8);
		} else {
			/* normal case: encrypt direct to target buffer */

			qdrbg_i_init_completion(&ctx->aes_ctx.result.completion);

			/*
			 * Note: personalize these called routines for
			 * specific testing.
			 */

			qdrbg_i_crypto_ablkcipher_clear_flags(ctx->aes_ctx.tfm,
								~0);

			/* Encrypt some clear text! */

			qdrbg_memcpy(ctx->aes_ctx.input.virt_addr,
				ctx->seed.key_V.V,
				16);
			qdrbg_sg_init_one(&sg_in,
				ctx->aes_ctx.input.virt_addr,
				16);
			qdrbg_sg_init_one(&sg_out,
				ctx->aes_ctx.output.virt_addr,
				16);
			qdrbg_i_ablkcipher_request_set_crypt(ctx->aes_ctx.req,
						&sg_in,
						&sg_out,
						CTR_DRBG_BLOCK_LEN_BYTES,
						NULL);

			rc = qdrbg_i_crypto_ablkcipher_encrypt(
							ctx->aes_ctx.req);

			switch (rc) {
			case 0:
				break;
			case -EINPROGRESS:
			case -EBUSY:
				rc = qdrbg_wait_for_completion_interruptible(
					&ctx->aes_ctx.result.completion);
				if (!rc && !ctx->aes_ctx.result.err) {
					qdrbg_m_INIT_COMPLETION(
					ctx->aes_ctx.result.completion);
					break;
				}
				/* fall through */
			default:
				break;
			}

			if (!qdrbg_memcmp(ctx->prev_drn,
				ctx->aes_ctx.output.virt_addr,
				16)) {
				qdrbg_panic("%s: FIPS DRBG continuous test failed!\n",
					__func__);
			}
			else
				qdrbg_memcpy(ctx->prev_drn,
					ctx->aes_ctx.output.virt_addr,
					16);

			qdrbg_memcpy((uint8_t *)buffer + 16*i,
				ctx->aes_ctx.output.virt_addr,
				16);
			rv = 0;
		}
	}

	update_rv = update(ctx,
			additional_input,
			(additional_input_len_bits + 7) / 8); /* round up */
	if (update_rv != CTR_DRBG_SUCCESS) {
		qdrbg_m_pr_err("%s: update additional input err:%d\n",
			__func__, update_rv);
		return update_rv;
	}

	ctx->reseed_counter += 1;

	return CTR_DRBG_SUCCESS;
}

/*
 * Generate random bits, but with no provided data. See notes on
 * ctr_drbg_generate_w_data()
 */
enum ctr_drbg_status_t
ctr_drbg_generate(struct ctr_drbg_ctx_s *ctx,
		void *buffer,
		size_t len_bits)

{
	return ctr_drbg_generate_w_data(ctx, NULL, 0, buffer, len_bits);
}

void ctr_aes_deinit(struct ctr_drbg_ctx_s *ctx)
{
	if (ctx->aes_ctx.req) {
		qdrbg_i_ablkcipher_request_free(ctx->aes_ctx.req);
		ctx->aes_ctx.req = NULL;
	}
	if (ctx->aes_ctx.tfm) {
		qdrbg_i_crypto_free_ablkcipher(ctx->aes_ctx.tfm);
		ctx->aes_ctx.tfm = NULL;
	}
	if (ctx->aes_ctx.input.virt_addr) {
		qdrbg_kzfree(ctx->aes_ctx.input.virt_addr);
		ctx->aes_ctx.input.virt_addr = NULL;
	}
	if (ctx->aes_ctx.output.virt_addr) {
		qdrbg_kzfree(ctx->aes_ctx.output.virt_addr);
		ctx->aes_ctx.output.virt_addr = NULL;
	}
	if (ctx->df_aes_ctx.req) {
		qdrbg_i_ablkcipher_request_free(ctx->df_aes_ctx.req);
		ctx->df_aes_ctx.req = NULL;
	}
	if (ctx->df_aes_ctx.tfm) {
		qdrbg_i_crypto_free_ablkcipher(ctx->df_aes_ctx.tfm);
		ctx->df_aes_ctx.tfm = NULL;
	}
	if (ctx->df_aes_ctx.input.virt_addr) {
		qdrbg_kzfree(ctx->df_aes_ctx.input.virt_addr);
		ctx->df_aes_ctx.input.virt_addr = NULL;
	}
	if (ctx->df_aes_ctx.output.virt_addr) {
		qdrbg_kzfree(ctx->df_aes_ctx.output.virt_addr);
		ctx->df_aes_ctx.output.virt_addr = NULL;
	}

}

/*
 * Zeroizes the context structure. In some future implemenation it
 * could also free resources.  So do call it.
 */
void
ctr_drbg_uninstantiate(struct ctr_drbg_ctx_s *ctx)
{
	ctr_aes_deinit(ctx);
	qdrbg_memset(ctx, 0, sizeof(*ctx));
}

/*
 * the derivation functions to handle biased entropy input.
 */
enum ctr_drbg_status_t df_bcc_func(struct ctr_drbg_ctx_s *ctx,
		uint8_t *key,
		uint8_t *input,
		uint32_t input_size,
		uint8_t *output)
{
	enum ctr_drbg_status_t ret_val = CTR_DRBG_SUCCESS;
	uint8_t *p;
	int rc;
	int i;
	int n;
	struct scatterlist sg_in, sg_out;

	if (0 != (input_size % CTR_DRBG_BLOCK_LEN_BYTES)) {
		qdrbg_m_pr_err("%s: invalid input_size:%u\n",
			__func__, input_size);
		return CTR_DRBG_INVALID_ARG;
	}

	n = input_size / CTR_DRBG_BLOCK_LEN_BYTES;

	for (i = 0; i < CTR_DRBG_BLOCK_LEN_BYTES; i++)
		ctx->df_aes_ctx.output.virt_addr[i] = 0;

	rc = qdrbg_i_crypto_ablkcipher_setkey(ctx->df_aes_ctx.tfm,
					key,
					AES128_KEY_SIZE);
	if (rc) {
		qdrbg_m_pr_err("%s: crypto_ablkcipher_setkey err:%d\n",
			__func__, rc);
		return CTR_DRBG_GENERAL_ERROR;
	}

	p = input;
	while (n > 0) {
		for (i = 0; i < CTR_DRBG_BLOCK_LEN_BYTES; i++, p++)
			ctx->df_aes_ctx.input.virt_addr[i] =
				ctx->df_aes_ctx.output.virt_addr[i] ^ (*p);

		qdrbg_i_init_completion(&ctx->df_aes_ctx.result.completion);

		/*
		 * Note: personalize these called routines for
		 * specific testing.
		 */

		qdrbg_i_crypto_ablkcipher_clear_flags(ctx->df_aes_ctx.tfm, ~0);

		/* Encrypt some clear text! */

		qdrbg_sg_init_one(&sg_in, ctx->df_aes_ctx.input.virt_addr, 16);
		qdrbg_sg_init_one(&sg_out,
				ctx->df_aes_ctx.output.virt_addr,
				16);

		qdrbg_i_ablkcipher_request_set_crypt(ctx->df_aes_ctx.req,
					&sg_in,
					&sg_out,
					CTR_DRBG_BLOCK_LEN_BYTES,
					NULL);

		rc = qdrbg_i_crypto_ablkcipher_encrypt(ctx->df_aes_ctx.req);

		switch (rc) {
		case 0:
			break;
		case -EINPROGRESS:
		case -EBUSY:
			rc = qdrbg_wait_for_completion_interruptible(
				&ctx->df_aes_ctx.result.completion);
			if (!rc && !ctx->df_aes_ctx.result.err) {
				qdrbg_m_INIT_COMPLETION(
				ctx->df_aes_ctx.result.completion);
				break;
			}
			/* fall through */
		default:
			break;
		}

		qdrbg_i_init_completion(&ctx->df_aes_ctx.result.completion);
		n--;
	}

	for (i = 0; i < CTR_DRBG_BLOCK_LEN_BYTES; i++)
		output[i] = ctx->df_aes_ctx.output.virt_addr[i];

	return ret_val;
}

/* output_size must <= 512 bits (<= 64) */
enum ctr_drbg_status_t
block_cipher_df(struct ctr_drbg_ctx_s *ctx,
		const uint8_t *input,
		uint32_t input_size,
		uint8_t *output,
		uint32_t output_size)
{
	enum ctr_drbg_status_t ret_val = CTR_DRBG_SUCCESS;
	uint32_t          s_len = 0;
	uint32_t          s_pad_len = 0;
	uint8_t           temp[32];
	uint32_t          out_len = 0;
	uint8_t           siv_string[64];
	uint8_t          *p_s_string = NULL;
	int               rc;
	struct scatterlist sg_in, sg_out;

	if (output_size > 64) {
		qdrbg_m_pr_err("%s: invalid output_size:%u\n",
			__func__, output_size);
		return CTR_DRBG_INVALID_ARG;
	}

	s_len = input_size + 9;

	s_pad_len = s_len % 16;

	if (0 != s_pad_len)
		s_len += (16 - s_pad_len);

	/* add the length of IV */
	s_len += 16;

	qdrbg_memset(siv_string, 0, 64);

	p_s_string = siv_string + 16;

	p_s_string[3] = input_size;
	p_s_string[7] = output_size;
	qdrbg_memcpy(p_s_string + 8, input, input_size);
	p_s_string[8 + input_size] = 0x80;
	if (0 < s_pad_len)
		qdrbg_memset(p_s_string + 9 + input_size, '\0', s_pad_len);

	ret_val = df_bcc_func(ctx, df_initial_k, siv_string, s_len, temp);

	if (CTR_DRBG_SUCCESS != ret_val) {
		qdrbg_m_pr_err("%s: df_bcc_func err:%d\n",
			__func__, ret_val);
		goto out;
	}

	siv_string[3] = 0x1;
	ret_val = df_bcc_func(ctx, df_initial_k, siv_string, s_len, temp + 16);

	if (CTR_DRBG_SUCCESS != ret_val) {
		qdrbg_m_pr_err("%s: df_bcc_func err:%d\n",
			__func__, ret_val);
		goto out;
	}

	out_len = 0;
	rc = qdrbg_i_crypto_ablkcipher_setkey(ctx->df_aes_ctx.tfm,
				temp,
				AES128_KEY_SIZE);
	if (rc) {
		qdrbg_m_pr_err("%s: crypto_ablkcipher_setkey err:%d\n",
			__func__, rc);
		goto out;
	}
	qdrbg_memcpy(ctx->df_aes_ctx.input.virt_addr, temp + 16, 16);

	while (out_len < output_size) {

		qdrbg_i_init_completion(&ctx->df_aes_ctx.result.completion);

		/*
		 * Note: personalize these called routines for
		 * specific testing.
		 */

		qdrbg_i_crypto_ablkcipher_clear_flags(ctx->df_aes_ctx.tfm, ~0);

		/* Encrypt some clear text! */

		qdrbg_sg_init_one(&sg_in, ctx->df_aes_ctx.input.virt_addr, 16);
		qdrbg_sg_init_one(&sg_out,
				ctx->df_aes_ctx.output.virt_addr,
				16);
		qdrbg_i_ablkcipher_request_set_crypt(ctx->df_aes_ctx.req,
					&sg_in,
					&sg_out,
					CTR_DRBG_BLOCK_LEN_BYTES,
					NULL);

		rc = qdrbg_i_crypto_ablkcipher_encrypt(ctx->df_aes_ctx.req);

		switch (rc) {
		case 0:
			break;
		case -EINPROGRESS:
		case -EBUSY:
			rc = qdrbg_wait_for_completion_interruptible(
				&ctx->df_aes_ctx.result.completion);
			if (!rc && !ctx->df_aes_ctx.result.err) {
				qdrbg_m_INIT_COMPLETION(
					ctx->df_aes_ctx.result.completion);
				break;
			}
			/* fall through */
		default:
			break;
		}


		qdrbg_i_init_completion(&ctx->df_aes_ctx.result.completion);

		qdrbg_memcpy(output + out_len,
			ctx->df_aes_ctx.output.virt_addr,
			16);
		qdrbg_memcpy(ctx->df_aes_ctx.input.virt_addr,
			output + out_len,
			16);
		out_len += 16;
	}

out:
	qdrbg_memset(siv_string, 0, 64);
	qdrbg_memset(temp, 0, 32);
	return ret_val;
}

