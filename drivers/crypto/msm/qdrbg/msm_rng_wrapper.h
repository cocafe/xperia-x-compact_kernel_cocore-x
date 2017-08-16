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
#ifndef __MSM_RNG_WRAPPER_HEADER__
#define __MSM_RNG_WRAPPER_HEADER__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/err.h>
#include <linux/types.h>
#include <soc/qcom/socinfo.h>
#include <linux/msm-bus.h>
#include <linux/qrng.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/of.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/qcedev.h>
#include <linux/delay.h>
#include <linux/hw_random.h>
#include <linux/semaphore.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/crypto.h>
#include <linux/platform_data/qcom_crypto_device.h>

struct _fips_drbg_ctx;

#define FIPS140_DRBG_ENABLED  (1)
#define FIPS140_DRBG_DISABLED (0)

#define Q_HW_DRBG_BLOCK_BYTES (32)

void qdrbg_m_pr_info(const char *fmt, ...);
void qdrbg_m_pr_err(const char *fmt, ...);
void qdrbg_m_pr_debug(const char *fmt, ...);

u32  qdrbg_m_readl_relaxed(void __iomem *addr);
void qdrbg_m_writel_relaxed(unsigned long v, void __iomem *c);
void qdrbg_m_mb(void);
struct class *qdrbg_m_class_create(struct module *owner, char *name);
void qdrbg_m_INIT_COMPLETION(struct completion x);

void qdrbg_m_dev_err(struct device *dev, const char *format, ...);

int qdrbg_i_clk_prepare_enable(struct clk *clk);
void qdrbg_i_clk_disable_unprepare(struct clk *clk);
int qdrbg_i_register_chrdev(unsigned int major, const char *name,
				const struct file_operations *fops);
void qdrbg_i_unregister_chrdev(unsigned int major, const char *name);
void qdrbg_i_iounmap(void __iomem *base);
int qdrbg_i_msm_bus_scale_client_update_request(uint32_t cl,
						unsigned int index);
void *qdrbg_i_kzalloc(size_t size, gfp_t flags);
void __iomem *qdrbg_i_ioremap(phys_addr_t offset, unsigned long size);
long __must_check qdrbg_i_IS_ERR(const void *ptr);
void qdrbg_i_platform_set_drvdata(struct platform_device *pdev,
					void *data);
struct msm_bus_scale_pdata *qdrbg_i_msm_bus_cl_get_pdata(
				struct platform_device *pdev);
uint32_t qdrbg_i_msm_bus_scale_register_client(
				struct msm_bus_scale_pdata *pdata);
long __must_check qdrbg_i_PTR_ERR(const void *ptr);
void qdrbg_i_sema_init(struct semaphore *sem, int val);
void *qdrbg_i_platform_get_drvdata(const struct platform_device *pdev);
void qdrbg_i_msm_bus_scale_unregister_client(uint32_t cl);
struct ablkcipher_request *qdrbg_i_ablkcipher_request_alloc(
			struct crypto_ablkcipher *tfm, gfp_t gfp);
void qdrbg_i_ablkcipher_request_set_callback(
		struct ablkcipher_request *req,
		u32 flags, crypto_completion_t complete, void *data);
void *qdrbg_i_kmalloc(size_t s, gfp_t gfp);
void qdrbg_i_ablkcipher_request_free(struct ablkcipher_request *req);
void qdrbg_i_crypto_free_ablkcipher(struct crypto_ablkcipher *tfm);
void qdrbg_i_init_completion(struct completion *x);
void qdrbg_i_crypto_ablkcipher_clear_flags(struct crypto_ablkcipher *tfm,
						u32 flags);
void qdrbg_i_ablkcipher_request_set_crypt(
		struct ablkcipher_request *req,
		struct scatterlist *src, struct scatterlist *dst,
		unsigned int nbytes, void *iv);
int qdrbg_i_crypto_ablkcipher_encrypt(struct ablkcipher_request *req);
int qdrbg_i_crypto_ablkcipher_setkey(struct crypto_ablkcipher *tfm,
				const u8 *key, unsigned int keylen);
void qdrbg_i_mutex_lock(struct mutex *lock);
void qdrbg_i_mutex_unlock(struct mutex *lock);
void qdrbg_i_mutex_init(struct mutex *lock);
int qdrbg_msm_bus_scale_client_update_request(uint32_t cl, unsigned int index);
void qdrbg_down(struct semaphore *sem);
void qdrbg_up(struct semaphore *sem);
void qdrbg_clk_put(struct clk *clk);
void qdrbg_kzfree(const void *p);
void qdrbg_panic(const char *fmt, ...);
void *qdrbg_memcpy(void *pdst, const void *psrc, size_t pn);
struct resource *qdrbg_platform_get_resource(struct platform_device *dev,
				unsigned int type, unsigned int num);
struct clk *qdrbg_clk_get(struct device *dev, const char *id);
int qdrbg_hwrng_register(struct hwrng *rng);
struct device *qdrbg_device_create(struct class *class,
				struct device *parent,
				dev_t devt,
				void *drvdata,
				const char *fmt, ...);
void qdrbg_cdev_init(struct cdev *cdev, const struct file_operations *fops);
void qdrbg_hwrng_unregister(struct hwrng *rng);
int qdrbg_platform_driver_register(struct platform_driver *drv);
void qdrbg_platform_driver_unregister(struct platform_driver *drv);
void* qdrbg_memset(void *dst, int c, size_t n);
int qdrbg_memcmp(const void *s1, const void *s2, size_t n);
void qdrbg_complete(struct completion * complt);
struct crypto_ablkcipher *qdrbg_crypto_alloc_ablkcipher(const char *alg_name,
						u32 type,
						u32 mask);
void qdrbg_sg_init_one(struct scatterlist *sg,
			const void *buf,
			unsigned int buflen);
int qdrbg_wait_for_completion_interruptible(struct completion *x);

void qdrbg_crypto_inc(u8 *a, unsigned int size);

/*
 * kernel module API
 */
extern int do_msm_rng_init(struct module *msm_module);
extern void do_msm_rng_exit(void);

#endif  /* ifndef __MSM_RNG_WRAPPER_HEADER__ */
