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
#include <linux/module.h>
#include <linux/clk.h>
#include <linux/types.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/crypto.h>
#include <linux/kernel.h>
#include <linux/rtnetlink.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/debugfs.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/cache.h>
#include <soc/qcom/scm.h>
#include <linux/fips_status.h>

#include "qcrypto_wrapper.h"

#ifdef CONFIG_FIPS_ENABLE

enum fips_status g_fips140_status = FIPS140_STATUS_FAIL;

/*
 * wrapper functions
 */
void* qcryptow_memset(void* dst, int c, size_t n)
{
	return memset(dst, c, n);
}

int qcrypto_dma_map_sg(struct device *dev, struct scatterlist *sg, int nents, enum dma_data_direction direction)
{
	return dma_map_sg(dev, sg, nents, direction);
}

void qcrypto_dma_unmap_sg(struct device *dev, struct scatterlist *sg, int nents, enum dma_data_direction direction)
{
	dma_unmap_sg(dev, sg, nents, direction);
}

struct scatterlist *qcryptow_scatterwalk_sg_next(struct scatterlist *sg)
{
	return scatterwalk_sg_next(sg);
}

u32  qcrypto_readl_relaxed(void __iomem *addr)
{
	return readl_relaxed(addr);
}

void qcrypto_writel_relaxed(unsigned long v, void __iomem *c)
{
	writel_relaxed(v, c);
}

void qcrypto_mb(void)
{
	mb();
}

void qcryptow_pr_debug(const char *fmt, ...)
{
/*
	va_list argp;

	va_start(argp, fmt);
	vprintk(fmt, argp);
	va_end(argp);
*/
}

void qcryptow_pr_info(const char *fmt, ...)
{
	va_list argp;

	va_start(argp, fmt);
	vprintk(fmt, argp);
	va_end(argp);
}

void qcryptow_pr_warn(const char *fmt, ...)
{
	va_list argp;

	va_start(argp, fmt);
	vprintk(fmt, argp);
	va_end(argp);
}

void qcryptow_pr_err(const char *fmt, ...)
{
	va_list argp;

	va_start(argp, fmt);
	vprintk(fmt, argp);
	va_end(argp);
}

void qcryptow_dev_info(struct device *dev, const char *format, ...)
{
	va_list argp;

	va_start(argp, format);
	dev_info(dev, format, argp);
	va_end(argp);
}

uint32_t qcrypto_BIT(unsigned int val)
{
	return BIT(val);
}

int qcrypto_sps_transfer_one(struct sps_pipe *h, phys_addr_t addr, u32 size, void *user, u32 flags)
{
	return sps_transfer_one(h, addr, size, user, flags);
}

void *qcryptow_memcpy(void *pdst, const void *psrc, size_t pn)
{
	return memcpy(pdst, psrc, pn);
}

struct crypto_aead *qcrypto_crypto_aead_reqtfm(struct aead_request *req)
{
	return crypto_aead_reqtfm(req);
}

unsigned int qcrypto_crypto_aead_ivsize(struct crypto_aead *tfm)
{
	return crypto_aead_ivsize(tfm);
}

void qcrypto_dma_unmap_single(struct device *dev, dma_addr_t handle, size_t size, enum dma_data_direction dir)
{
	dma_unmap_single(dev, handle, size, dir);
}

unsigned int qcrypto_m_sg_dma_len(struct scatterlist *sg)
{
	return sg_dma_len(sg);
}

dma_addr_t qcrypto_m_sg_dma_address(struct scatterlist *sg)
{
	return sg_dma_address(sg);
}

uint32_t qcrypto_ALIGN(uint32_t stack, int size)
{
	return ALIGN(stack, size);
}

int qcrypto_sps_transfer(struct sps_pipe *h, struct sps_transfer *transfer)
{
	return sps_transfer(h, transfer);
}

struct sps_pipe *qcrypto_sps_alloc_endpoint(void)
{
	return sps_alloc_endpoint();
}

int qcrypto_sps_get_config(struct sps_pipe *h, struct sps_connect *config)
{
	return sps_get_config(h, config);
}

void *qcrypto_dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma_handle, gfp_t gfp)
{
	return dma_alloc_coherent(dev, size, dma_handle, gfp);
}

int qcrypto_sps_connect(struct sps_pipe *h, struct sps_connect *connect)
{
	return sps_connect(h, connect);
}

int qcrypto_sps_free_endpoint(struct sps_pipe *ctx)
{
	return sps_free_endpoint(ctx);
}

int qcrypto_sps_disconnect(struct sps_pipe *h)
{
	return sps_disconnect(h);
}

void qcryptow_mutex_lock(struct mutex *lock)
{
	mutex_lock(lock);
}

void qcrypto_i_iounmap(void __iomem *base)
{
	iounmap(base);
}

void qcryptow_list_del(struct list_head *entry)
{
	list_del(entry);
}

void qcryptow_kzfree(const void *p)
{
	kzfree(p);
}

void qcryptow_mutex_unlock(struct mutex*  lock)
{
        mutex_unlock(lock);
}

void *qcryptow_i_kzalloc(size_t size, gfp_t flags)
{
	return kzalloc(size, flags);
}

void __iomem *qcrypto_ioremap_nocache(phys_addr_t phys_addr, unsigned long size)
{
	return ioremap_nocache(phys_addr, size);
}

int qcrypto_sps_register_bam_device(const struct sps_bam_props *bam_props, unsigned long *dev_handle)
{
	return sps_register_bam_device(bam_props, dev_handle);
}

// void qcryptow_list_add_tail(struct listnode *head, struct listnode *item)
// {
//	list_add_tail(head, item);
// }

int qcrypto_sps_register_event(struct sps_pipe *h, struct sps_register_event *reg)
{
	return sps_register_event(h, reg);
}

dma_addr_t qcrypto_dma_map_single(struct device *dev, void *cpu_addr, size_t size, enum dma_data_direction dir)
{
	return dma_map_single(dev, cpu_addr, size, dir);
}

void *qcrypto_sg_virt(struct scatterlist *sg)
{
	return sg_virt(sg);
}

bool qcrypto_of_property_read_bool(const struct device_node *np, const char *propname)
{
	return of_property_read_bool(np, propname);
}

int qcrypto_of_property_read_u32(const struct device_node *np, const char *propname, u32 *out_value)
{
	return of_property_read_u32(np, propname, out_value);
}

struct resource *qcrypto_platform_get_resource_byname(struct platform_device *dev, unsigned int type, const char *name)
{
	return platform_get_resource_byname(dev, type, name);
}

resource_size_t qcrypto_resource_size(const struct resource *res)
{
	return resource_size(res);
}

struct resource *qcrypto_platform_get_resource(struct platform_device *dev, unsigned int type, unsigned int num)
{
	return platform_get_resource(dev, type, num);
}

struct clk *qcrypto_clk_get(struct device *dev, const char *id)
{
	return clk_get(dev, id);
}

void qcrypto_clk_put(struct clk * clk)
{
	clk_put(clk);
}

long __must_check qcryptow_i_IS_ERR(const void *ptr)
{
	return IS_ERR(ptr);
}

int qcrypto_clk_set_rate(struct clk *clk, unsigned long rate)
{
	return clk_set_rate(clk, rate);
}

long __must_check qcryptow_i_PTR_ERR(const void *ptr)
{
	return PTR_ERR(ptr);
}

int qcrypto_i_clk_prepare_enable(struct clk *clk)
{
	return clk_prepare_enable(clk);
}

void qcrypto_i_clk_disable_unprepare(struct clk *clk)
{
	clk_disable_unprepare(clk);
}

void *qcryptow_ERR_PTR(uintptr_t error)
{
	return ERR_PTR(error);
}

void qcryptow_get_random_bytes(void *buf, int nbytes)
{
	return get_random_bytes(buf, nbytes);
}

void qcryptow_INIT_LIST_HEAD(struct list_head *list)
{
	INIT_LIST_HEAD(list);
}

struct crypto_ahash *qcryptow__crypto_ahash_cast(struct crypto_tfm *tfm)
{
	return __crypto_ahash_cast(tfm);
}

void *qcryptow_crypto_tfm_ctx(struct crypto_tfm *tfm)
{
	return crypto_tfm_ctx(tfm);
}

struct hash_alg_common *qcryptow_crypto_hash_alg_common(struct crypto_ahash *tfm)
{
	return crypto_hash_alg_common(tfm);
}

void qcryptow_crypto_ahash_set_reqsize(struct crypto_ahash *tfm, unsigned int reqsize)
{
	crypto_ahash_set_reqsize(tfm, reqsize);
}

// int qcryptow_list_empty(struct list *list)
// {
//	return list_empty(list);
// }

void qcryptow_ahash_request_free(struct ahash_request *req)
{
	ahash_request_free(req);
}

struct ahash_request *qcryptow_ahash_request_alloc(struct crypto_ahash *tfm, gfp_t gfp)
{
	return ahash_request_alloc(tfm, gfp);
}

void qcryptow_init_completion(struct completion *x)
{
	init_completion(x);
}

void qcryptow_ahash_request_set_callback(struct ahash_request *req, u32 flags, crypto_completion_t complete, void *data)
{
	return ahash_request_set_callback(req, flags, complete, data);
}

void qcryptow_crypto_ahash_clear_flags(struct crypto_ahash *tfm, u32 flags)
{
	crypto_ahash_clear_flags(tfm, flags);
}

struct crypto_ablkcipher *qcryptow_crypto_alloc_ablkcipher(const char *alg_name, u32 type, u32 mask)
{
	return crypto_alloc_ablkcipher(alg_name, type, mask);
}

void qcryptow_crypto_free_ablkcipher(struct crypto_ablkcipher *tfm)
{
	crypto_free_ablkcipher(tfm);
}

int qcryptow_scnprintf(char * buf, size_t size, const char * fmt, ...)
{
	va_list args;
	ssize_t ssize = size;
	int i;

	va_start(args, fmt);
	i = vsnprintf(buf, size, fmt, args);
	va_end(args);

	return (i >= ssize) ? (ssize - 1) : i;
}
/*
 * function wrappers from qcrypto.c
 */
int qcryptow_scm_call(uint32_t svc_id, uint32_t cmd_id, const void *cmd_buf, size_t cmd_len, void *resp_buf, size_t resp_len)
{
	return scm_call(svc_id, cmd_id, cmd_buf, cmd_len, resp_buf, resp_len);
}

void qcryptow_spin_lock_irqsave(spinlock_t *lock, unsigned long flags)
{
	spin_lock_irqsave(lock, flags);
}

void qcryptow_spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags)
{
	spin_unlock_irqrestore(lock, flags);
}

void qcryptow_pm_stay_awake(struct device *dev)
{
	pm_stay_awake(dev);
}

int qcryptow_msm_bus_scale_client_update_request(uint32_t cl, unsigned int index)
{
	return msm_bus_scale_client_update_request(cl, index);
}

void qcryptow_pm_relax(struct device *dev)
{
	pm_relax(dev);
}

bool qcryptow_schedule_work(struct work_struct *work)
{
	return schedule_work(work);
}

unsigned long qcryptow_msecs_to_jiffies(const unsigned int m)
{
	return msecs_to_jiffies(m);
}

int qcryptow_mod_timer(struct timer_list *timer, unsigned long expires)
{
	return mod_timer(timer, expires);
}

void qcryptow_dev_err(struct device *dev, const char *format, ...)
{
	va_list argp;

	va_start(argp, format);
	dev_err(dev, format, argp);
	va_end(argp);
}

void qcryptow_dev_warn(struct device *dev, const char *format, ...)
{
        va_list argp;

        va_start(argp, format);
        dev_warn(dev, format, argp);
        va_end(argp);
}

size_t qcryptow_sg_copy_from_buffer(struct scatterlist *sgl, unsigned int nents, void *buf, size_t buflen)
{
	return sg_copy_from_buffer(sgl, nents, buf, buflen);
}

size_t qcryptow_sg_copy_to_buffer(struct scatterlist *sgl, unsigned int nents, void *buf, size_t buflen)
{
	return sg_copy_to_buffer(sgl, nents, buf, buflen);
}

void qcryptow_tasklet_kill(struct tasklet_struct *t)
{
	tasklet_kill(t);
}

bool qcryptow_cancel_work_sync(struct work_struct *work)
{
	return cancel_work_sync(work);
}

int qcryptow_del_timer_sync(struct timer_list *timer)
{
	return del_timer_sync(timer);
}

void qcryptow_msm_bus_scale_unregister_client(uint32_t cl)
{
	msm_bus_scale_unregister_client(cl);
}

int qcryptow_crypto_unregister_alg(struct crypto_alg *alg)
{
	return crypto_unregister_alg(alg);
}

int qcryptow_crypto_unregister_ahash(struct ahash_alg *alg)
{
	return crypto_unregister_ahash(alg);
}

void *qcryptow_platform_get_drvdata(const struct platform_device *pdev)
{
	return platform_get_drvdata(pdev);
}

void qcryptow_crypto_ablkcipher_set_flags(struct crypto_ablkcipher *tfm, u32 flags)
{
	crypto_ablkcipher_set_flags(tfm, flags);
}

struct crypto_tfm *qcryptow_crypto_ablkcipher_tfm(struct crypto_ablkcipher *tfm)
{
	return crypto_ablkcipher_tfm(tfm);
}

int qcryptow_crypto_ablkcipher_setkey(struct crypto_ablkcipher *tfm, const u8 *key, unsigned int keylen)
{
	return crypto_ablkcipher_setkey(tfm, key, keylen);
}

unsigned long qcryptow_des_ekey(u32 *pe, const u8 *k)
{
	return des_ekey(pe, k);
}

u32 qcryptow_crypto_tfm_alg_type(struct crypto_tfm *tfm)
{
	return crypto_tfm_alg_type(tfm);
}

struct crypto_ahash *qcryptow_crypto_ahash_reqtfm(struct ahash_request *req)
{
	return crypto_ahash_reqtfm(req);
}

unsigned int qcryptow_crypto_ahash_digestsize(struct crypto_ahash *tfm)
{
	return crypto_ahash_digestsize(tfm);
}

void qcryptow_tasklet_schedule(struct tasklet_struct *t)
{
	return tasklet_schedule(t);
}

struct crypto_ablkcipher *qcryptow_crypto_ablkcipher_reqtfm(struct ablkcipher_request *req)
{
	return crypto_ablkcipher_reqtfm(req);
}

void *qcryptow_ablkcipher_request_ctx(struct ablkcipher_request *req)
{
	return ablkcipher_request_ctx(req);
}

struct crypto_aead *qcryptow_crypto_aead_reqtfm(struct aead_request *req)
{
	return crypto_aead_reqtfm(req);
}

void *qcryptow_aead_request_ctx(struct aead_request *req)
{
	return aead_request_ctx(req);
}

unsigned int qcryptow_crypto_aead_authsize(struct crypto_aead *tfm)
{
	return crypto_aead_authsize(tfm);
}

void qcryptow_scatterwalk_map_and_copy(void *buf, struct scatterlist *sg, unsigned int start, unsigned int nbytes, int out)
{
	return scatterwalk_map_and_copy(buf, sg, start, nbytes, out);
}

int qcryptow_memcmp(const void *s1, const void *s2, size_t n)
{
	return memcmp(s1, s2, n);
}

__be32 qcryptow_cpu_to_be32(unsigned int n)
{
	return cpu_to_be32(n);
}

__be16 qcryptow_cpu_to_be16(uint32_t n)
{
	return cpu_to_be16(n);
}

void qcryptow_sg_set_buf(struct scatterlist *sg, const void *buf, unsigned int buflen)
{
	return sg_set_buf(sg, buf, buflen);
}

void qcryptow_sg_mark_end(struct scatterlist *sg)
{
	sg_mark_end(sg);
}

unsigned int qcryptow_crypto_ablkcipher_ivsize(struct crypto_ablkcipher *tfm)
{
	return crypto_ablkcipher_ivsize(tfm);
}

void *qcryptow_ahash_request_ctx(struct ahash_request *req)
{
	return ahash_request_ctx(req);
}

unsigned int qcryptow_crypto_aead_ivsize(struct crypto_aead *tfm)
{
	return crypto_aead_ivsize(tfm);
}

struct crypto_async_request *qcryptow_crypto_get_backlog(struct crypto_queue *queue)
{
	return crypto_get_backlog(queue);
}

struct crypto_async_request *qcryptow_crypto_dequeue_request(struct crypto_queue *queue)
{
	return crypto_dequeue_request(queue);
}

int qcryptow_crypto_enqueue_request(struct crypto_queue *queue, struct crypto_async_request *request)
{
	return crypto_enqueue_request(queue, request);
}

void qcryptow_ablkcipher_request_set_tfm(struct ablkcipher_request *req, struct crypto_ablkcipher *tfm)
{
	return ablkcipher_request_set_tfm(req, tfm);
}

int qcryptow_crypto_ablkcipher_encrypt(struct ablkcipher_request *req)
{
	return crypto_ablkcipher_encrypt(req);
}

int qcryptow_crypto_ablkcipher_decrypt(struct ablkcipher_request *req)
{
	return crypto_ablkcipher_decrypt(req);
}

void *qcryptow_crypto_aead_ctx(struct crypto_aead *tfm)
{
	return crypto_aead_ctx(tfm);
}

struct crypto_authenc_key_param * qcryptow_RTA_DATA(struct rtattr *rta)
{
	return RTA_DATA(rta);
}

uint32_t qcryptow_be32_to_cpu(uint32_t v)
{
	return be32_to_cpu(v);
}

unsigned short qcryptow_RTA_ALIGN(unsigned short x)
{
	return RTA_ALIGN(x);
}

void qcryptow_crypto_aead_set_flags(struct crypto_aead *tfm, u32 flags)
{
	return crypto_aead_set_flags(tfm, flags);
}

struct crypto_tfm *qcryptow_crypto_aead_tfm(struct crypto_aead *tfm)
{
	return crypto_aead_tfm(tfm);
}

u64 qcryptow_cpu_to_be64(u64 x)
{
	return cpu_to_be64(x);
}

void qcryptow_sg_chain(struct scatterlist *prv, unsigned int prv_nents, struct scatterlist *sgl)
{
	sg_chain(prv, prv_nents, sgl);
}

void qcryptow_complete(struct completion *cp)
{
	complete(cp);
}

void qcryptow_ahash_request_set_crypt(struct ahash_request *req, struct scatterlist *src, u8 *result, unsigned int nbytes)
{
	ahash_request_set_crypt(req, src, result, nbytes);
}

int __sched qcryptow_wait_for_completion_interruptible(struct completion *x)
{
	return wait_for_completion_interruptible(x);
}

void qcryptow_INIT_COMPLETION(struct completion x)
{
	INIT_COMPLETION(x);
}

size_t qcryptow_strlcat(char *dst, const char *src, size_t siz)
{
	return strlcat(dst, src, siz);
}

size_t qcryptow_strlcpy(char *dst, const char *src, size_t siz)
{
	return strlcpy(dst, src, siz);
}

void qcryptow_platform_set_drvdata(struct platform_device *pdev, void *data)
{
	platform_set_drvdata(pdev, data);
}

void qcryptow_init_timer(struct timer_list *t)
{
	init_timer(t);
}

void qcryptow_INIT_WORK(struct work_struct *w, void (*func)(struct work_struct *k))
{
	INIT_WORK(w, func);
}

void qcryptow_tasklet_init(struct tasklet_struct *t, void (*func)(unsigned long), unsigned long data)
{
	tasklet_init(t, func, data);
}

void qcryptow_crypto_init_queue(struct crypto_queue *queue, unsigned int max_qlen)
{
	crypto_init_queue(queue, max_qlen);
}

struct msm_bus_scale_pdata *qcryptow_msm_bus_cl_get_pdata(struct platform_device *pdev)
{
	return msm_bus_cl_get_pdata(pdev);
}

uint32_t qcryptow_msm_bus_scale_register_client(struct msm_bus_scale_pdata *pdata)
{
	return msm_bus_scale_register_client(pdata);
}

int qcryptow_crypto_register_alg(struct crypto_alg *alg)
{
	return crypto_register_alg(alg);
}

int qcryptow_crypto_register_ahash(struct ahash_alg *alg)
{
	return crypto_register_ahash(alg);
}

void qcryptow_panic(const char *fmt, ...)
{
	panic(fmt);
}

ssize_t qcryptow_simple_read_from_buffer(void __user *to, size_t count, loff_t *ppos, const void *from, size_t available)
{
	return simple_read_from_buffer(to, count, ppos, from, available);
}

struct dentry *qcryptow_debugfs_create_dir(const char *name, struct dentry *parent)
{
	return debugfs_create_dir(name, parent);
}

struct dentry *qcryptow_debugfs_create_file(const char *name, umode_t mode, struct dentry *parent, void *data, const struct file_operations *fops)
{
	return debugfs_create_file(name, mode, parent, data, fops);
}

void qcryptow_debugfs_remove_recursive(struct dentry *dentry)
{
	debugfs_remove_recursive(dentry);
}

void qcryptow_spin_lock_init(spinlock_t *lock)
{
	spin_lock_init(lock);
}

void qcryptow_mutex_init(struct mutex *lock)
{
	mutex_init(lock);
}

int qcryptow_platform_driver_register(struct platform_driver *drv)
{
	return platform_driver_register(drv);
}

void qcryptow_platform_driver_unregister(struct platform_driver *drv)
{
	platform_driver_unregister(drv);
}

/* wrapper functions from qcedev.c */
void __sched qcryptow_wait_for_completion(struct completion *x)
{
	wait_for_completion(x);
}

void *qcryptow_kmalloc(size_t s, gfp_t gfp)
{
	return kmalloc(s, gfp);
}

// int qcryptow_access_ok(int t, void * addr, uint32_t len)
// {
//	return accesss_ok(t, addr, len);
// }

unsigned qcryptow__IOC_TYPE(unsigned nr)
{
	return _IOC_TYPE(nr);
}

int qcryptow_misc_register(struct miscdevice * misc)
{
	return misc_register(misc);
}

struct crypto_ahash *qcryptow_crypto_alloc_ahash(const char *alg_name, u32 type, u32 mask)
{
	return crypto_alloc_ahash(alg_name, type, mask);
}

void qcryptow_sg_init_one(struct scatterlist *sg, const void *buf, unsigned int buflen)
{
	sg_init_one(sg, buf, buflen);
}

int qcryptow_crypto_ahash_setkey(struct crypto_ahash *tfm, const u8 *key, unsigned int keylen)
{
	return crypto_ahash_setkey(tfm, key, keylen);
}

int qcryptow_crypto_ahash_digest(struct ahash_request *req)
{
	return crypto_ahash_digest(req);
}

void qcryptow_crypto_free_ahash(struct crypto_ahash *tfm)
{
	crypto_free_ahash(tfm);
}

void qcryptow_dma_unmap_sg(struct device *dev, struct scatterlist *sglist, int nents, enum dma_data_direction dir)
{
	dma_unmap_sg(dev, sglist, nents, dir);
}

void qcryptow_dma_free_coherent(struct device *dev, size_t size, void *vaddr, dma_addr_t dma_handle)
{
	dma_free_coherent(dev, size, vaddr, dma_handle);
}

int qcryptow_misc_deregister(struct miscdevice *misc)
{
	return misc_deregister(misc);
}

int qcryptow_device_init_wakeup(struct device *dev, bool val)
{
        return device_init_wakeup(dev, val);
}

/*
 * end of wrapper functions
 */

static int __init _qcrypto_module_init(void)
{
	int ret;

	ret = qcrypto_init();
	printk("_qcrypto_init return = %d\n", ret);
	if (ret)
		return ret;

	set_qcrypto_func_dm((void *)qcrypto_cipher_set_device_hw,
				(void *)qcrypto_cipher_set_flag,
				(void *)qcrypto_get_num_engines,
				(void *)qcrypto_get_engine_list);

	ret = qcedev_init();
	return ret;
}

static void __exit _qcrypto_module_exit(void)
{
	qcedev_exit();
	qcrypto_exit();
}

#else
static int __init _qcrypto_module_init(void)
{
	return 0;
}

static void __exit _qcrypto_module_exit(void)
{
	return;
}

#endif
module_init(_qcrypto_module_init);
module_exit(_qcrypto_module_exit);


MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Qualcomm Crypto driver");
