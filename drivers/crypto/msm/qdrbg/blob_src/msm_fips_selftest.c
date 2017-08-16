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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "../msm_rng_wrapper.h"
#include "fips_drbg.h"
#include "ctr_drbg.h"
#include "msm_rng.h"
#include "msm_fips_selftest.h"

#define CTRAES128_ENTROPY_BYTES       (16)
#define CTRAES128_NONCE_BYTES         (8)
#define CTRAES128_MAX_OUTPUT_BYTES    (64)

struct ctr_drbg_testcase_s {
	char *name;
	char *entropy_string;
	char *nonce_string;
	char *reseed_entropy_string;
	char *expected_string;
};

static struct ctr_drbg_testcase_s t0 = {
	.name = "use_pr_0",
	.entropy_string = "\x8f\xb9\x57\x3a\x54\x62\x53\xcd"
			  "\xbf\x62\x15\xa1\x80\x5a\x41\x38",
	.nonce_string   = "\x7c\x2c\xe6\x54\x02\xbc\xa6\x83",
	.reseed_entropy_string = "\xbc\x5a\xd8\x9a\xe1\x8c\x49\x1f"
				 "\x90\xa2\xae\x9e\x7e\x2c\xf9\x9d",
	.expected_string = "\x07\x62\x82\xe8\x0e\x65\xd7\x70"
			   "\x1a\x35\xb3\x44\x63\x68\xb6\x16"
			   "\xf8\xd9\x62\x23\xb9\xb5\x11\x64"
			   "\x23\xa3\xa2\x32\xc7\x2c\xea\xbf"
			   "\x4a\xcc\xc4\x0a\xc6\x19\xd6\xaa"
			   "\x68\xae\xdb\x8b\x26\x70\xb8\x07"
			   "\xcc\xe9\x9f\xc2\x1b\x8f\xa5\x16"
			   "\xef\x75\xb6\x8f\xc0\x6c\x87\xc7",
};

static struct ctr_drbg_testcase_s t1 = {
	.name = "use_pr_1",
	.entropy_string = "\xa3\x56\xf3\x9a\xce\x48\x59\xb1"
			  "\xe1\x99\x49\x40\x22\x8e\xa4\xeb",
	.nonce_string   = "\xff\x33\xe9\x51\x39\xf7\x67\xf1",
	.reseed_entropy_string = "\x66\x8f\x0f\xe2\xd8\xa9\xa9\x29"
				 "\x20\xfc\xb9\xf3\x55\xd6\xc3\x4c",
	.expected_string = "\xa1\x06\x61\x65\x7b\x98\x0f\xac"
			   "\xce\x77\x91\xde\x7f\x6f\xe6\x1e"
			   "\x88\x15\xe5\xe2\x4c\xce\xb8\xa6"
			   "\x63\xf2\xe8\x2f\x5b\xfb\x16\x92"
			   "\x06\x2a\xf3\xa8\x59\x05\xe0\x5a"
			   "\x92\x9a\x07\x65\xc7\x41\x29\x3a"
			   "\x4b\x1d\x15\x3e\x02\x14\x7b\xdd"
			   "\x74\x5e\xbd\x70\x07\x4d\x6c\x08",
};

static struct ctr_drbg_testcase_s *testlist[] = {
	&t0, &t1
};

static int allzeroP(void *p, size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i)
		if (((uint8_t *)p)[i] != 0)
			return 0;

	return 1;
}

/*
 * basic test.  return value is error count.
 */
int fips_ctraes128_df_known_answer_test(struct ctr_debg_test_inputs_s *tcase)
{
	struct ctr_drbg_ctx_s ctx;
	enum ctr_drbg_status_t rv;

	if (tcase->observed_string_len > CTRAES128_MAX_OUTPUT_BYTES)
		return 1;

	memset(&ctx, 0, sizeof(ctx));

	ctx.continuous_test_started = 1;

	rv = ctr_drbg_instantiate(&ctx,
				  tcase->entropy_string,
				  8 * CTRAES128_ENTROPY_BYTES,
				  tcase->nonce_string,
				  8 * CTRAES128_NONCE_BYTES,
				  1<<19);
	if (rv != CTR_DRBG_SUCCESS) {
		qdrbg_m_pr_err("test instantiate failed with code %d\n", rv);
		return 1;
	}

	rv = ctr_drbg_reseed(&ctx,
			     tcase->reseed_entropy_string,
			     8 * CTRAES128_ENTROPY_BYTES);
	if (rv != CTR_DRBG_SUCCESS) {
		qdrbg_m_pr_err("test reseed failed with code %d\n", rv);
		return 1;
	}

	rv = ctr_drbg_generate(&ctx,
			       tcase->observed_string,
			       tcase->observed_string_len * 8);
	if (rv != CTR_DRBG_SUCCESS) {
		qdrbg_m_pr_err("test generate (2) failed with code %d\n", rv);
		return 1;
	}

	rv = ctr_drbg_generate(&ctx,
			       tcase->observed_string,
			       tcase->observed_string_len * 8);
	if (rv != CTR_DRBG_SUCCESS) {
		qdrbg_m_pr_err("test generate (2) failed with code %d\n", rv);
		return 1;
	}

	ctr_drbg_uninstantiate(&ctx);

	if (!allzeroP(&ctx.seed, sizeof(ctx.seed))) {
		qdrbg_m_pr_err("test Final failed to zeroize the context\n");
		return 1;
	}

	return 0;

}
EXPORT_SYMBOL(fips_ctraes128_df_known_answer_test);

static int fips_drbg_healthcheck_sanitytest(void)
{
	struct ctr_drbg_ctx_s *p_ctx = NULL;
	enum ctr_drbg_status_t rv = CTR_DRBG_SUCCESS;
	char entropy_string[MSM_ENTROPY_BUFFER_SIZE];
	char nonce[MSM_NONCE_BUFFER_SIZE];
	char buffer[32];

	p_ctx = kzalloc(sizeof(struct ctr_drbg_ctx_s), GFP_KERNEL);
	if (NULL == p_ctx) {
		rv = CTR_DRBG_GENERAL_ERROR;
		qdrbg_m_pr_err("p_ctx kzalloc fail\n");
		goto outbuf;
	}

	/*
	 * test DRGB Instantiaion function error handling.
	 * Sends a NULL pointer as DTR-DRBG context.
	 */
	rv = ctr_drbg_instantiate(NULL,
				  entropy_string,
				  8 * CTRAES128_ENTROPY_BYTES,
				  nonce,
				  8 * CTRAES128_NONCE_BYTES,
				  1<<19);
	if (CTR_DRBG_SUCCESS == rv) {
		rv = CTR_DRBG_INVALID_ARG;
		qdrbg_m_pr_err("CTR context: failed NULL pointer\n");
		goto outbuf;
	}

	/*
	 * test DRGB Instantiaion function error handling.
	 * Sends a NULL pointer as entropy input.
	 */
	rv = ctr_drbg_instantiate(p_ctx,
				  NULL,
				  8 * CTRAES128_ENTROPY_BYTES,
				  nonce,
				  8 * CTRAES128_NONCE_BYTES,
				  1<<19);
	if (CTR_DRBG_SUCCESS == rv) {
		rv = CTR_DRBG_INVALID_ARG;
		qdrbg_m_pr_err("entropy string: failed NULL pointer\n");
		goto outbuf;
	}

	rv = ctr_drbg_instantiate(p_ctx,
				  entropy_string,
				  8 * CTRAES128_ENTROPY_BYTES,
				  NULL,
				  8 * CTRAES128_NONCE_BYTES,
				  1<<19);
	if (CTR_DRBG_SUCCESS == rv) {
		rv = CTR_DRBG_INVALID_ARG;
		qdrbg_m_pr_err("nonce string: failed NULL pointer\n");
		goto outbuf;
	}

	/*
	 * test DRGB Instantiaion function error handling.
	 * Sends very long seed length.
	 */
	rv = ctr_drbg_instantiate(p_ctx,
				  entropy_string,
				  8 * CTRAES128_ENTROPY_BYTES,
				  nonce,
				  32 * CTRAES128_NONCE_BYTES,
				  1<<19);
	if (CTR_DRBG_SUCCESS == rv) {
		rv = CTR_DRBG_INVALID_ARG;
		qdrbg_m_pr_err("failed on incorrect seed size\n");
		goto outbuf;
	}


	rv = ctr_drbg_instantiate(p_ctx,
				  entropy_string,
				  8 * CTRAES128_ENTROPY_BYTES,
				  nonce,
				  8 * CTRAES128_NONCE_BYTES,
				  1<<19);
	if (CTR_DRBG_SUCCESS != rv) {
		qdrbg_m_pr_err("Instantiation failed, CTR-DRBG instance\n");
		goto outbuf;
	}

	/*
	 * test DRGB generator function error handling.
	 * set output string as NULL.
	 */
	rv = ctr_drbg_generate(p_ctx, NULL, 256);
	if (CTR_DRBG_SUCCESS == rv) {
		qdrbg_m_pr_err("failed to handle incorrect buffer pointer\n");
		rv = CTR_DRBG_INVALID_ARG;
		goto outdrbg;
	}

	rv = ctr_drbg_generate(p_ctx, &buffer,  1 << 20);
	if (CTR_DRBG_SUCCESS == rv) {
		qdrbg_m_pr_err("failed to handle too long output length\n");
		rv = CTR_DRBG_INVALID_ARG;
		goto outdrbg;
	}

	rv = ctr_drbg_generate(p_ctx, &buffer,  177);
	if (CTR_DRBG_SUCCESS == rv) {
		qdrbg_m_pr_err("failed to handle incorrect output length\n");
		rv = CTR_DRBG_INVALID_ARG;
		goto outdrbg;
	}

	rv = CTR_DRBG_SUCCESS;

outdrbg:
	ctr_drbg_uninstantiate(p_ctx);

outbuf:
	if (p_ctx)
		kzfree(p_ctx);
	p_ctx = NULL;

	memset(buffer, 0, 32);
	memset(nonce, 0, MSM_NONCE_BUFFER_SIZE);
	memset(entropy_string, 0, MSM_ENTROPY_BUFFER_SIZE);

	return rv;
}

int fips_self_test(void)
{
	struct ctr_debg_test_inputs_s cavs_input;
	uint8_t entropy[CTRAES128_ENTROPY_BYTES];
	uint8_t nonce[CTRAES128_NONCE_BYTES];
	uint8_t reseed_entropy[CTRAES128_ENTROPY_BYTES];
	uint8_t expected[CTRAES128_MAX_OUTPUT_BYTES];
	uint8_t observed[CTRAES128_MAX_OUTPUT_BYTES];
	unsigned int i;
	int errors = 0;
	int ret;

	cavs_input.entropy_string = entropy;
	cavs_input.nonce_string = nonce;
	cavs_input.reseed_entropy_string = reseed_entropy;
	cavs_input.observed_string = observed;
	cavs_input.observed_string_len = CTRAES128_MAX_OUTPUT_BYTES;


	ret = fips_drbg_healthcheck_sanitytest();
	if (CTR_DRBG_SUCCESS != ret) {
		qdrbg_m_pr_err("DRBG health check fail\n");
		errors++;
		return errors;
	}

	for (i = 0;
	     i < sizeof(testlist)/sizeof(struct ctr_drbg_testcase_s *);
	     ++i) {
		memcpy(entropy,
			testlist[i]->entropy_string,
			CTRAES128_ENTROPY_BYTES);
		memcpy(nonce,
			testlist[i]->nonce_string,
			CTRAES128_NONCE_BYTES);
		memcpy(reseed_entropy,
			testlist[i]->reseed_entropy_string,
			CTRAES128_ENTROPY_BYTES);
		memcpy(expected,
			testlist[i]->expected_string,
			CTRAES128_MAX_OUTPUT_BYTES);

		ret = fips_ctraes128_df_known_answer_test(&cavs_input);
		if (0 != ret)
			return 1;

		if (memcmp(expected,
			cavs_input.observed_string,
			CTRAES128_MAX_OUTPUT_BYTES) != 0) {
			errors++;
			return 1;
		}
	}

	return errors;

}

