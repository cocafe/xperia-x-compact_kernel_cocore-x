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
#include <linux/init.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/hw_random.h>
#include <linux/clk.h>
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
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/of.h>
#include <linux/gfp.h>
#include <linux/string.h>
#include <linux/semaphore.h>
#include <linux/qcedev.h>
#include <linux/delay.h>
#include <crypto/algapi.h>

#include <linux/platform_data/qcom_crypto_device.h>

#include "msm_rng_wrapper.h"

#ifdef CONFIG_FIPS_ENABLE

#define DRIVER_NAME "msm_rng"

/*
 * Start wrapper functions.
 * Wrapper functions wraps all Linux kernel functions.
 * This is to make the QDRBG binary blob portable to
 * different kernel values.
 */
void qdrbg_down(struct semaphore *sem)
{
	down(sem);
}

void qdrbg_clk_put(struct clk *clk)
{
	clk_put(clk);
}

void qdrbg_kzfree(const void *p)
{
	kzfree(p);
}

void qdrbg_panic(const char *fmt, ...)
{
	panic(fmt);
}

void *qdrbg_memcpy(void *pdst, const void *psrc, size_t pn)
{
	return memcpy(pdst, psrc, pn);
}

struct resource *qdrbg_platform_get_resource(struct platform_device *dev,
					unsigned int type,
					unsigned int num)
{
	return platform_get_resource(dev, type, num);
}

struct clk *qdrbg_clk_get(struct device *dev, const char *id)
{
	return clk_get(dev, id);
}

int qdrbg_hwrng_register(struct hwrng *rng)
{
	return hwrng_register(rng);
}

struct device *qdrbg_device_create(struct class *class, struct device *parent,
				   dev_t devt,
				   void *drvdata,
				   const char *fmt, ...)
{
	return device_create(class, parent, devt, drvdata, fmt);
}

void qdrbg_cdev_init(struct cdev *cdev, const struct file_operations *fops)
{
	return cdev_init(cdev, fops);
}

void qdrbg_hwrng_unregister(struct hwrng *rng)
{
	hwrng_unregister(rng);
}

int qdrbg_platform_driver_register(struct platform_driver *drv)
{
	return platform_driver_register(drv);
}

void qdrbg_platform_driver_unregister(struct platform_driver *drv)
{
	platform_driver_unregister(drv);
}

void* qdrbg_memset(void *dst, int c, size_t n)
{
	return memset(dst, c, n);
}

int qdrbg_memcmp(const void *s1, const void *s2, size_t n)
{
	return memcmp(s1, s2, n);
}

void qdrbg_complete(struct completion *complt)
{
	complete(complt);
}

struct crypto_ablkcipher *qdrbg_crypto_alloc_ablkcipher(
				const char *alg_name,
				u32 type,
				u32 mask)
{
	return crypto_alloc_ablkcipher(alg_name, type, mask);
}

void qdrbg_sg_init_one(struct scatterlist *sg,
			const void *buf,
			unsigned int buflen)
{
	sg_init_one(sg, buf, buflen);
}

int qdrbg_wait_for_completion_interruptible(struct completion *x)
{
	return wait_for_completion_interruptible(x);
}


int qdrbg_i_clk_prepare_enable(struct clk *clk)
{
	return clk_prepare_enable(clk);
}

void qdrbg_i_clk_disable_unprepare(struct clk *clk)
{
	clk_disable_unprepare(clk);
}

int qdrbg_i_register_chrdev(unsigned int major, const char *name,
				const struct file_operations *fops)
{
	return register_chrdev(major, name, fops);
}

void qdrbg_i_unregister_chrdev(unsigned int major, const char *name)
{
	unregister_chrdev(major, name);
}

void qdrbg_i_iounmap(void __iomem *base)
{
	iounmap(base);
}

int qdrbg_i_msm_bus_scale_client_update_request(uint32_t cl,
						unsigned int index)
{
	return msm_bus_scale_client_update_request(cl, index);
}

void *qdrbg_i_kzalloc(size_t size, gfp_t flags)
{
	return kzalloc(size, flags);
}

void __iomem *qdrbg_i_ioremap(phys_addr_t offset, unsigned long size)
{
	return ioremap(offset, size);
}

long __must_check qdrbg_i_IS_ERR(const void *ptr)
{
	return IS_ERR(ptr);
}

void qdrbg_i_platform_set_drvdata(struct platform_device *pdev,
					void *data)
{
	platform_set_drvdata(pdev, data);
}

struct msm_bus_scale_pdata
	*qdrbg_i_msm_bus_cl_get_pdata(struct platform_device *pdev)
{
	return msm_bus_cl_get_pdata(pdev);
}

uint32_t qdrbg_i_msm_bus_scale_register_client(
		struct msm_bus_scale_pdata *pdata)
{
	return msm_bus_scale_register_client(pdata);
}

long __must_check qdrbg_i_PTR_ERR(const void *ptr)
{
	return PTR_ERR(ptr);
}

void qdrbg_i_sema_init(struct semaphore *sem, int val)
{
	sema_init(sem, val);
}

void *qdrbg_i_platform_get_drvdata(const struct platform_device *pdev)
{
	return platform_get_drvdata(pdev);
}

void qdrbg_i_msm_bus_scale_unregister_client(uint32_t cl)
{
	msm_bus_scale_unregister_client(cl);
}

struct ablkcipher_request *qdrbg_i_ablkcipher_request_alloc(
			struct crypto_ablkcipher *tfm, gfp_t gfp)
{
	return ablkcipher_request_alloc(tfm, gfp);
}

void qdrbg_i_ablkcipher_request_set_callback(
		struct ablkcipher_request *req,
		u32 flags, crypto_completion_t complete, void *data)
{
	ablkcipher_request_set_callback(req, flags, complete, data);
}

void *qdrbg_i_kmalloc(size_t s, gfp_t gfp)
{
	return kmalloc(s, gfp);
}

void qdrbg_i_ablkcipher_request_free(struct ablkcipher_request *req)
{
	ablkcipher_request_free(req);
}

void qdrbg_i_crypto_free_ablkcipher(struct crypto_ablkcipher *tfm)
{
	crypto_free_ablkcipher(tfm);
}

void qdrbg_i_init_completion(struct completion *x)
{
	init_completion(x);
}

void qdrbg_i_crypto_ablkcipher_clear_flags(struct crypto_ablkcipher *tfm,
						u32 flags)
{
	crypto_ablkcipher_clear_flags(tfm, flags);
}

void qdrbg_i_ablkcipher_request_set_crypt(
		struct ablkcipher_request *req,
		struct scatterlist *src, struct scatterlist *dst,
		unsigned int nbytes, void *iv)
{
	ablkcipher_request_set_crypt(req, src, dst, nbytes, iv);
}

int qdrbg_i_crypto_ablkcipher_encrypt(struct ablkcipher_request *req)
{
	return crypto_ablkcipher_encrypt(req);
}

int qdrbg_i_crypto_ablkcipher_setkey(struct crypto_ablkcipher *tfm,
				const u8 *key, unsigned int keylen)
{
	return crypto_ablkcipher_setkey(tfm, key, keylen);
}

void qdrbg_i_mutex_lock(struct mutex *lock)
{
	mutex_lock(lock);
}

void qdrbg_i_mutex_unlock(struct mutex *lock)
{
	mutex_unlock(lock);
}

void qdrbg_i_mutex_init(struct mutex *lock)
{
	mutex_init(lock);
}

void qdrbg_m_dev_err(struct device *dev, const char *format, ...)
{
	va_list argp;

	va_start(argp, format);
	dev_err(dev, format, argp);
	va_end(argp);
}

void qdrbg_m_pr_info(const char *fmt, ...)
{
	va_list argp;

	va_start(argp, fmt);
	vprintk(fmt, argp);
	va_end(argp);
}

void qdrbg_m_pr_err(const char *fmt, ...)
{
	va_list argp;

	va_start(argp, fmt);
	vprintk(fmt, argp);
	va_end(argp);
}

void qdrbg_m_pr_debug(const char *fmt, ...)
{
	/* Hook for printing debug */
}

void qdrbg_m_mb(void)
{
	mb();
}

struct class *qdrbg_m_class_create(struct module *owner, char *name)
{
	return class_create((owner), (name));
}

void qdrbg_m_INIT_COMPLETION(struct completion x)
{
	INIT_COMPLETION(x);
}

void qdrbg_m_writel_relaxed(unsigned long v, void __iomem *c)
{
	writel_relaxed(v, c);
}

u32  qdrbg_m_readl_relaxed(void __iomem *addr)
{
	return readl_relaxed(addr);
}

void qdrbg_crypto_inc(u8 *a, unsigned int size)
{
	crypto_inc(a, size);
}

static int msm_rng_init(void)
{
	struct module *local_module = NULL;

	local_module = THIS_MODULE;
	return do_msm_rng_init(local_module);
}

module_init(msm_rng_init);

static void msm_rng_exit(void)
{
	do_msm_rng_exit();
}

module_exit(msm_rng_exit);

#else
static int msm_rng_init(void)
{
	return 0;
}

static void msm_rng_exit(void)
{
	return;
}
module_init(msm_rng_init);
module_exit(msm_rng_exit);
#endif

MODULE_DESCRIPTION("Qualcomm MSM Random Number Driver");
MODULE_LICENSE("GPL v2");
