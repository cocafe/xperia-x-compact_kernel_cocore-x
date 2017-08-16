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
#ifndef __MSM_CTR_DRBG_H__
#define __MSM_CTR_DRBG_H__

/* This is the module that is actually follows the details of NIST SP
 * 800-90 so it can claim to use a FIPS-approved algorithm.
 */

/* Added ctr_drbg_generate_w_data which supplies
 * additional input to the generate operation.
 */


#define CTR_DRBG_MAX_REQ_LEN_BITS	(1 << 19)
#define CTR_DRBG_SEED_LEN_BITS		256
#define CTR_DRBG_BLOCK_LEN_BITS		128
#define CTR_DRBG_BLOCK_LEN_BYTES	(CTR_DRBG_BLOCK_LEN_BITS/8)
#define CTR_DRBG_MAX_RESEED_INTERVAL	(1ULL << 48)

#define MSM_AES128_BLOCK_SIZE   (16)
#define MSM_ENTROPY_BUFFER_SIZE (16)
#define MSM_NONCE_BUFFER_SIZE   (8)

enum ctr_drbg_status_t {
	CTR_DRBG_SUCCESS = 0,
	CTR_DRBG_NEEDS_RESEED,
	CTR_DRBG_INVALID_ARG,
	CTR_DRBG_INVALID_NONCE_ENTROPY,
	CTR_DRBG_INVALID_SEED_INTERVAL,
	CTR_DRBG_GENERAL_ERROR = 0xFF,
};

union ctr_drbg_seed_t {
	uint8_t as_bytes[32];
	uint32_t as_words[8];
	uint64_t as_64[4];
	struct {
		uint8_t key[16];
		uint8_t V[16];
	} key_V;
};

struct msm_ctr_tcrypt_result_s {
	struct completion completion;
	int err;
};

struct msm_ctr_buffer_s {
	unsigned char *virt_addr;
};

struct aes_struct_s {
	struct crypto_ablkcipher	*tfm;
	struct ablkcipher_request	*req;
	struct msm_ctr_buffer_s		input;
	struct msm_ctr_buffer_s		output;
	struct msm_ctr_tcrypt_result_s	result;
};

struct ctr_drbg_ctx_s {
	unsigned long long reseed_counter;  /* starts at 1 as per SP
					     * 800-90
					     */
	unsigned long long	reseed_interval;
	union ctr_drbg_seed_t	seed;
	struct aes_struct_s	aes_ctx;
	struct aes_struct_s	df_aes_ctx;
	uint8_t			prev_drn[MSM_AES128_BLOCK_SIZE];
	uint8_t			continuous_test_started;
};

enum ctr_drbg_status_t ctr_drbg_instantiate(struct ctr_drbg_ctx_s *ctx,
					const uint8_t *entropy,
					size_t entropy_len_bits,
					const uint8_t *nonce,
					size_t nonce_len_bits,
					unsigned long long reseed_interval);

enum ctr_drbg_status_t ctr_drbg_reseed(struct ctr_drbg_ctx_s *ctx,
				const void *entropy,
				size_t entropy_len);

enum ctr_drbg_status_t ctr_drbg_generate_w_data(struct ctr_drbg_ctx_s *ctx,
			void *additional_input,
			size_t additional_input_len_bits,
			void *buffer,
			size_t len_bits);

enum ctr_drbg_status_t ctr_drbg_generate(struct ctr_drbg_ctx_s *ctx,
				void *buffer,
				size_t len);

void ctr_drbg_uninstantiate(struct ctr_drbg_ctx_s *ctx);

enum ctr_drbg_status_t block_cipher_df(struct ctr_drbg_ctx_s *ctx,
				const uint8_t *input,
				uint32_t input_size,
				uint8_t *output,
				uint32_t output_size
				);
void ctr_aes_deinit(struct ctr_drbg_ctx_s *ctx);

#endif /* __MSM_CTR_DRBG_H__ */
