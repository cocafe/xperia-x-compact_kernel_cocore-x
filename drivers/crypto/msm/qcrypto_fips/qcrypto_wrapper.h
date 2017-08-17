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
#ifndef __MSM_QCRYPTO_WRAPPER_HEADER__
#define __MSM_QCRYPTO_WRAPPER_HEADER__

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
#include <linux/msm-bus.h>
#include <soc/qcom/scm.h>
#include <linux/fips_status.h>

#include <linux/kernel.h>
#include <linux/mod_devicetable.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/bitops.h>
#include <linux/clk/msm-clk.h>
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
#include <crypto/internal/aead.h>
#include <linux/qcrypto.h>

#include <soc/qcom/socinfo.h>
#include <linux/msm-sps.h>
#include <linux/workqueue.h>

void* qcryptow_memset(void* dst, int c, size_t n);
int qcrypto_dma_map_sg(struct device *dev, struct scatterlist *sg, int nents, enum dma_data_direction direction);
void qcrypto_dma_ummap_sg(struct device *dev, struct scatterlist *sg, int nents, enum dma_data_direction direction);
struct scatterlist *qcryptow_scatterwalk_sg_next(struct scatterlist *sg);
u32  qcrypto_readl_relaxed(void __iomem *addr);
void qcrypto_writel_relaxed(unsigned long v, void __iomem *c);
void qcrypto_mb(void);
void qcryptow_pr_debug(const char *fmt, ...);
void qcryptow_pr_info(const char *fmt, ...);
void qcryptow_pr_warn(const char *fmt, ...);
void qcryptow_pr_err(const char *fmt, ...);
void qcryptow_dev_info(struct device *dev, const char *format, ...);
uint32_t qcrypto_BIT(unsigned int val);
int qcrypto_sps_transfer_one(struct sps_pipe *h, phys_addr_t addr, u32 size, void *user, u32 flags);
void *qcryptow_memcpy(void *pdst, const void *psrc, size_t pn);
struct crypto_aead *qcrypto_crypto_aead_reqtfm(struct aead_request *req);
unsigned int qcrypto_crypto_aead_ivsize(struct crypto_aead *tfm);
void qcrypto_dma_unmap_single(struct device *dev, dma_addr_t handle, size_t size, enum dma_data_direction dir);
unsigned int qcrypto_m_sg_dma_len(struct scatterlist *sg);
dma_addr_t qcrypto_m_sg_dma_address(struct scatterlist *sg);
uint32_t qcrypto_ALIGN(uint32_t stack, int size);
int qcrypto_sps_transfer(struct sps_pipe *h, struct sps_transfer *transfer);
struct sps_pipe *qcrypto_sps_alloc_endpoint(void);
int qcrypto_sps_get_config(struct sps_pipe *h, struct sps_connect *config);
void *qcrypto_dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma_handle, gfp_t gfp);
int qcrypto_sps_connect(struct sps_pipe *h, struct sps_connect *connect);
int qcrypto_sps_free_endpoint(struct sps_pipe *ctx);
int qcrypto_sps_disconnect(struct sps_pipe *h);
void qcryptow_mutex_lock(struct mutex *lock);
void qcryptow_mutex_unlock(struct mutex*  lock);
void qcrypto_i_iounmap(void __iomem *base);
void qcryptow_list_del(struct list_head *entry);
void qcryptow_kzfree(const void *p);
void *qcryptow_i_kzalloc(size_t size, gfp_t flags);
void __iomem *qcrypto_ioremap_nocache(phys_addr_t phys_addr, unsigned long size);
int qcrypto_sps_register_bam_device(const struct sps_bam_props *bam_props, unsigned long *dev_handle);
int qcrypto_sps_register_event(struct sps_pipe *h, struct sps_register_event *reg);
dma_addr_t qcrypto_dma_map_single(struct device *dev, void *cpu_addr, size_t size, enum dma_data_direction dir);
void *qcrypto_sg_virt(struct scatterlist *sg);
bool qcrypto_of_property_read_bool(const struct device_node *np, const char *propname);
int qcrypto_of_property_read_u32(const struct device_node *np, const char *propname, u32 *out_value);
struct resource *qcrypto_platform_get_resource_byname(struct platform_device *dev, unsigned int type, const char *name);
resource_size_t qcrypto_resource_size(const struct resource *res);
struct resource *qcrypto_platform_get_resource(struct platform_device *dev, unsigned int type, unsigned int num);
struct clk *qcrypto_clk_get(struct device *dev, const char *id);
void qcrypto_clk_put(struct clk * clk);
long __must_check qcryptow_i_IS_ERR(const void *ptr);
int qcrypto_clk_set_rate(struct clk *clk, unsigned long rate);
long __must_check qcryptow_i_PTR_ERR(const void *ptr);
int qcrypto_i_clk_prepare_enable(struct clk *clk);
void qcrypto_i_clk_disable_unprepare(struct clk *clk);
void qcryptow_dma_unmap_sg(struct device *dev, struct scatterlist *sglist, int nents, enum dma_data_direction dir);
void qcryptow_dma_free_coherent(struct device *dev, size_t size, void *vaddr, dma_addr_t dma_handle);

/* function wrappers from qcrypto.c */
int qcryptow_scm_call(uint32_t svc_id, uint32_t cmd_id, const void *cmd_buf, size_t cmd_len, void *resp_buf, size_t resp_len);
void qcryptow_spin_lock_irqsave(spinlock_t *lock, unsigned long flags);
void qcryptow_spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags);
void qcryptow_pm_stay_awake(struct device *dev);
int qcryptow_msm_bus_scale_client_update_request(uint32_t cl, unsigned int index);
void qcryptow_pm_relax(struct device *dev);
bool qcryptow_schedule_work(struct work_struct *work);
unsigned long qcryptow_msecs_to_jiffies(const unsigned int m);
int qcryptow_mod_timer(struct timer_list *timer, unsigned long expires);
void qcryptow_dev_err(struct device *dev, const char *format, ...);
void qcryptow_dev_warn(struct device *dev, const char *format, ...);
size_t qcryptow_sg_copy_from_buffer(struct scatterlist *sgl, unsigned int nents, void *buf, size_t buflen);
size_t qcryptow_sg_copy_to_buffer(struct scatterlist *sgl, unsigned int nents, void *buf, size_t buflen);
void *qcryptow_ERR_PTR(uintptr_t error);
void qcryptow_get_random_bytes(void *buf, int nbytes);
void qcryptow_INIT_LIST_HEAD(struct list_head *list);
struct crypto_ahash *qcryptow__crypto_ahash_cast(struct crypto_tfm *tfm);
void *qcryptow_crypto_tfm_ctx(struct crypto_tfm *tfm);
struct hash_alg_common *qcryptow_crypto_hash_alg_common(struct crypto_ahash *tfm);
void qcryptow_crypto_ahash_set_reqsize(struct crypto_ahash *tfm, unsigned int reqsize);
void qcryptow_ahash_request_free(struct ahash_request *req);
struct ahash_request *qcryptow_ahash_request_alloc(struct crypto_ahash *tfm, gfp_t gfp);
void qcryptow_init_completion(struct completion *x);
void qcryptow_ahash_request_set_callback(struct ahash_request *req, u32 flags, crypto_completion_t complete, void *data);
void qcryptow_crypto_ahash_clear_flags(struct crypto_ahash *tfm, u32 flags);
struct crypto_ablkcipher *qcryptow_crypto_alloc_ablkcipher(const char *alg_name, u32 type, u32 mask);
void qcryptow_crypto_free_ablkcipher(struct crypto_ablkcipher *tfm);
int qcryptow_scnprintf(char * buf, size_t size, const char * fmt, ...);
void qcryptow_tasklet_kill(struct tasklet_struct *t);
bool qcryptow_cancel_work_sync(struct work_struct *work);
int qcryptow_del_timer_sync(struct timer_list *timer);
void qcryptow_msm_bus_scale_unregister_client(uint32_t cl);
int qcryptow_crypto_unregister_alg(struct crypto_alg *alg);
int qcryptow_crypto_unregister_ahash(struct ahash_alg *alg);
void *qcryptow_platform_get_drvdata(const struct platform_device *pdev);
void qcryptow_crypto_ablkcipher_set_flags(struct crypto_ablkcipher *tfm, u32 flags);
struct crypto_tfm *qcryptow_crypto_ablkcipher_tfm(struct crypto_ablkcipher *tfm);
int qcryptow_crypto_ablkcipher_setkey(struct crypto_ablkcipher *tfm, const u8 *key, unsigned int keylen);
unsigned long qcryptow_des_ekey(u32 *pe, const u8 *k);
u32 qcryptow_crypto_tfm_alg_type(struct crypto_tfm *tfm);
struct crypto_ahash *qcryptow_crypto_ahash_reqtfm(struct ahash_request *req);
unsigned int qcryptow_crypto_ahash_digestsize(struct crypto_ahash *tfm);
void qcryptow_tasklet_schedule(struct tasklet_struct *t);
struct crypto_ablkcipher *qcryptow_crypto_ablkcipher_reqtfm(struct ablkcipher_request *req);
void *qcryptow_ablkcipher_request_ctx(struct ablkcipher_request *req);
struct crypto_aead *qcryptow_crypto_aead_reqtfm(struct aead_request *req);
void *qcryptow_aead_request_ctx(struct aead_request *req);
unsigned int qcryptow_crypto_aead_authsize(struct crypto_aead *tfm);
void qcryptow_scatterwalk_map_and_copy(void *buf, struct scatterlist *sg, unsigned int start, unsigned int nbytes, int out);
int qcryptow_memcmp(const void *s1, const void *s2, size_t n);
__be32 qcryptow_cpu_to_be32(unsigned int n);
__be16 qcryptow_cpu_to_be16(uint32_t n);
void qcryptow_sg_set_buf(struct scatterlist *sg, const void *buf, unsigned int buflen);
void qcryptow_sg_mark_end(struct scatterlist *sg);
unsigned int qcryptow_crypto_ablkcipher_ivsize(struct crypto_ablkcipher *tfm);
void *qcryptow_ahash_request_ctx(struct ahash_request *req);
unsigned int qcryptow_crypto_aead_ivsize(struct crypto_aead *tfm);
struct crypto_async_request *qcryptow_crypto_get_backlog(struct crypto_queue *queue);
struct crypto_async_request *qcryptow_crypto_dequeue_request(struct crypto_queue *queue);
int qcryptow_crypto_enqueue_request(struct crypto_queue *queue, struct crypto_async_request *request);
void qcryptow_ablkcipher_request_set_tfm(struct ablkcipher_request *req, struct crypto_ablkcipher *tfm);
int qcryptow_crypto_ablkcipher_encrypt(struct ablkcipher_request *req);
int qcryptow_crypto_ablkcipher_decrypt(struct ablkcipher_request *req);
void *qcryptow_crypto_aead_ctx(struct crypto_aead *tfm);
struct crypto_authenc_key_param * qcryptow_RTA_DATA(struct rtattr *rta);
uint32_t qcryptow_be32_to_cpu(uint32_t v);
unsigned short qcryptow_RTA_ALIGN(unsigned short x);
void qcryptow_crypto_aead_set_flags(struct crypto_aead *tfm, u32 flags);
struct crypto_tfm *qcryptow_crypto_aead_tfm(struct crypto_aead *tfm);
u64 qcryptow_cpu_to_be64(u64 x);
void qcryptow_sg_chain(struct scatterlist *prv, unsigned int prv_nents, struct scatterlist *sgl);
void qcryptow_complete(struct completion *cp);
void qcryptow_ahash_request_set_crypt(struct ahash_request *req, struct scatterlist *src, u8 *result, unsigned int nbytes);
int __sched qcryptow_wait_for_completion_interruptible(struct completion *x);
void qcryptow_INIT_COMPLETION(struct completion x);
size_t qcryptow_strlcat(char *dst, const char *src, size_t siz);
size_t qcryptow_strlcpy(char *dst, const char *src, size_t siz);
void qcryptow_platform_set_drvdata(struct platform_device *pdev, void *data);
void qcryptow_init_timer(struct timer_list *t);
void qcryptow_INIT_WORK(struct work_struct *w, void (*func)(struct work_struct *k));
void qcryptow_tasklet_init(struct tasklet_struct *t, void (*func)(unsigned long), unsigned long data);
void qcryptow_crypto_init_queue(struct crypto_queue *queue, unsigned int max_qlen);
struct msm_bus_scale_pdata *qcryptow_msm_bus_cl_get_pdata(struct platform_device *pdev);
uint32_t qcryptow_msm_bus_scale_register_client(struct msm_bus_scale_pdata *pdata);
int qcryptow_crypto_register_alg(struct crypto_alg *alg);
int qcryptow_crypto_register_ahash(struct ahash_alg *alg);
void qcryptow_panic(const char *fmt, ...);
ssize_t qcryptow_simple_read_from_buffer(void __user *to, size_t count, loff_t *ppos, const void *from, size_t available);
struct dentry *qcryptow_debugfs_create_dir(const char *name, struct dentry *parent);
struct dentry *qcryptow_debugfs_create_file(const char *name, umode_t mode, struct dentry *parent, void *data, const struct file_operations *fops);
void qcryptow_debugfs_remove_recursive(struct dentry *dentry);
void qcryptow_spin_lock_init(spinlock_t *lock);
void qcryptow_mutex_init(struct mutex *lock);
int qcryptow_platform_driver_register(struct platform_driver *drv);
void qcryptow_platform_driver_unregister(struct platform_driver *drv);
int qcryptow_device_init_wakeup(struct device *dev, bool val);

/* function wrappers from qcedev.c */
void __sched qcryptow_wait_for_completion(struct completion *x);
void *qcryptow_kmalloc(size_t s, gfp_t gfp);
unsigned qcryptow__IOC_TYPE(unsigned nr);
int qcryptow_misc_register(struct miscdevice * misc);
int qcryptow_misc_deregister(struct miscdevice *misc);

/* wrapper functions from qcrypto_fips.c */
struct crypto_ahash *qcryptow_crypto_alloc_ahash(const char *alg_name, u32 type, u32 mask);
void qcryptow_sg_init_one(struct scatterlist *sg, const void *buf, unsigned int buflen);
int qcryptow_crypto_ahash_setkey(struct crypto_ahash *tfm, const u8 *key, unsigned int keylen);
int qcryptow_crypto_ahash_digest(struct ahash_request *req);
void qcryptow_crypto_free_ahash(struct crypto_ahash *tfm);
struct ablkcipher_request *qcryptow_ablkcipher_request_alloc(struct crypto_ablkcipher *tfm, gfp_t gfp);

extern int  qcedev_init(void);
extern void qcedev_exit(void);

extern int  qcrypto_init(void);
extern void qcrypto_exit(void);
extern void set_qcrypto_func_dm(void *dev, void *flag, void *engines, void *engine_list);
extern int qcrypto_cipher_set_device(struct ablkcipher_request *req, unsigned int dev);
extern int qcrypto_cipher_set_flag(struct ablkcipher_request *req, unsigned int flags);

#endif // __MSM_QCRYPTO_WRAPPER_HEADER__
