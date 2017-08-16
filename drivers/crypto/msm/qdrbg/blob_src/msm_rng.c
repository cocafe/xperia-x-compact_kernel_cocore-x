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
#include <linux/export.h>

#include <linux/kernel.h>
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
#include <linux/delay.h>
#include <linux/crypto.h>
#include <crypto/internal/rng.h>

#include <linux/platform_data/qcom_crypto_device.h>

#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

#include "../msm_rng_wrapper.h"
#include "msm_rng.h"
#include "ctr_drbg.h"
#include "fips_drbg.h"
#include "msm_fips_selftest.h"

#define DRIVER_NAME "msm_rng"

/* Device specific register offsets */
#define PRNG_DATA_OUT_OFFSET    0x0000
#define PRNG_STATUS_OFFSET	0x0004
#define PRNG_LFSR_CFG_OFFSET	0x0100
#define PRNG_CONFIG_OFFSET	0x0104

/* Device specific register masks and config values */
#define PRNG_LFSR_CFG_MASK	0xFFFF0000
#define PRNG_LFSR_CFG_CLOCKS	0x0000DDDD
#define PRNG_CONFIG_MASK	0xFFFFFFFD
#define PRNG_HW_ENABLE		0x00000002

#define MAX_HW_FIFO_DEPTH 16                     /* FIFO is 16 words deep */
#define MAX_HW_FIFO_SIZE (MAX_HW_FIFO_DEPTH * 4) /* FIFO is 32 bits wide  */

/*FIPS140-2 call back for DRBG self test */

enum {
	FIPS140_NOT_STARTED = 0,
	FIPS140_DRBG_STARTED
};

struct msm_rng_device msm_rng_device_info;
static struct msm_rng_device *msm_rng_dev_cached = NULL;
struct mutex cached_rng_lock;
static struct msm_rng_device *sp_msm_rng_dev = NULL;
static int fips_mode_enabled = FIPS140_NOT_STARTED;

static int _do_msm_fips_drbg_init(void *rng_dev);
static void _fips_drbg_init_error(struct msm_rng_device  *msm_rng_dev);

static long msm_rng_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	long ret = 0;

	switch (cmd) {
	case QRNG_IOCTL_RESET_BUS_BANDWIDTH:
		ret = qdrbg_i_msm_bus_scale_client_update_request(
				msm_rng_device_info.qrng_perf_client, 0);
		if (ret)
			qdrbg_m_pr_err("qrng_reset_bus_bw ret: %ld\n",
					ret);
		break;
	case QRNG_IOCTL_UPDATE_FIPS_STATUS:
		{
		enum fips_status status;
		int ret = 0;

		if (!access_ok(VERIFY_WRITE, (void __user *)arg,
			sizeof(enum fips_status)))
			return -EFAULT;

		if (__copy_from_user(&status, (void __user *)arg,
			sizeof(enum fips_status)))
			return -EFAULT;

		status &= 0xFF;

		if (status == FIPS140_STATUS_PASS) {
			qdrbg_m_pr_err("FIPS stat: FIPS140_STATUS_PASS\n");
			ret = _do_msm_fips_drbg_init(sp_msm_rng_dev);
			if (!ret)
				fips_mode_enabled = FIPS140_DRBG_STARTED;
			else
				fips_mode_enabled = FIPS140_NOT_STARTED;
		} else {
			fips_mode_enabled = FIPS140_NOT_STARTED;
		}

		status |= FIPS140_CMD_OK;

		if (__copy_to_user((void __user *)arg, &status,
			sizeof(enum fips_status)))
			return -EFAULT;

		}
		break;
	default:
		qdrbg_m_pr_err("Unsupported IOCTL call");
		break;
	}
	return ret;
}

#ifdef CONFIG_COMPAT
static long compat_msm_rng_ioctl(struct file *filp, unsigned int cmd,
					unsigned long arg)
{
	long ret = 0;

	ret = msm_rng_ioctl(filp, cmd, arg);

	return ret;
}
#endif
/*
 *
 *  This function calls hardware random bit generator directory and retuns
 *  it back to caller
 *
 */
int msm_rng_direct_read(struct msm_rng_device *msm_rng_dev, void *data, size_t max)
{
	struct platform_device *pdev;
	void __iomem *base;
	size_t currsize = 0;
	u32 val;
	u32 *retdata = data;
	int ret;
	int failed = 0;

	pdev = msm_rng_dev->pdev;
	base = msm_rng_dev->base;

	mutex_lock(&msm_rng_dev->rng_lock);

	if (msm_rng_dev->qrng_perf_client) {
		ret = qdrbg_i_msm_bus_scale_client_update_request(
				msm_rng_dev->qrng_perf_client, 1);
		if (ret)
			pr_err("bus_scale_client_update_req failed!\n");
	}
	/* enable PRNG clock */
	ret = clk_prepare_enable(msm_rng_dev->prng_clk);
	if (ret) {
		qdrbg_m_dev_err(&pdev->dev, "failed to enable clock\n");
		goto err;
	}
	/* read random data from h/w */
	do {
		/* check status bit if data is available */
		while (!(readl_relaxed(base + PRNG_STATUS_OFFSET)
					& 0x00000001)) {
			if (failed == 10) {
				pr_err("Data not available after retry\n");
				break;
			}
			qdrbg_m_pr_err("msm_rng:Data not available!\n");
			msleep_interruptible(10);
			failed++;
		}

		/* read FIFO */
		val = readl_relaxed(base + PRNG_DATA_OUT_OFFSET);
		if (!val)
			break;	/* no data to read so just bail */

		/* write data back to callers pointer */
		*(retdata++) = val;
		currsize += 4;

	} while (currsize < max);

	/* vote to turn off clock */
	clk_disable_unprepare(msm_rng_dev->prng_clk);
err:
	if (msm_rng_dev->qrng_perf_client) {
		ret = qdrbg_i_msm_bus_scale_client_update_request(
				msm_rng_dev->qrng_perf_client, 0);
		if (ret)
			qdrbg_m_pr_err("bus_scale_client_update_req err\n");
	}
	mutex_unlock(&msm_rng_dev->rng_lock);

	val = 0L;
	return currsize;
}

static int msm_rng_drbg_read(struct msm_rng_device *msm_rng_dev,
			void *data, size_t max)
{
	int ret = FIPS140_PRNG_ERR;

	/* no room for word data */
	if (max < 4)
		return 0;

	/* read random data from CTR-AES based DRBG */
	ret = fips_drbg_gen(msm_rng_dev->drbg_ctx, data, max);
	if (FIPS140_PRNG_OK != ret) {
		qdrbg_m_pr_err("random number generator error: %d\n", ret);
		return 0;
	}

	/* FIPS DRBG read succeeds, return data */
	return	max;
}

#ifdef CONFIG_FIPS_ENABLE
static void _fips_drbg_init_error(struct msm_rng_device  *msm_rng_dev)
{
	qdrbg_i_unregister_chrdev(QRNG_IOC_MAGIC, DRIVER_NAME);
	qdrbg_clk_put(msm_rng_dev->prng_clk);
	qdrbg_i_iounmap(msm_rng_dev->base);
	qdrbg_kzfree(msm_rng_dev->drbg_ctx);
	qdrbg_kzfree(msm_rng_dev);
	qdrbg_panic("software PRNG initialization error.\n");
}
#else
static inline void _fips_drbg_init_error(struct msm_rng_device *msm_rng_dev)
{
	return;
}

#endif

#ifdef CONFIG_FIPS_ENABLE
int _do_msm_fips_drbg_init(void *rng_dev)
{
	struct msm_rng_device *msm_rng_dev = NULL;

	int ret;

	msm_rng_dev = (struct msm_rng_device *)rng_dev;
	if (NULL == msm_rng_dev)
		return 1;

	ret = fips_drbg_init(msm_rng_dev);
	if (0 == ret) {
		ret = fips_self_test();
		if (ret) {
			msm_rng_dev->fips140_drbg_enabled =
				FIPS140_DRBG_DISABLED;
			_fips_drbg_init_error(msm_rng_dev);
		} else {
			msm_rng_dev->fips140_drbg_enabled =
				FIPS140_DRBG_ENABLED;
		}
	} else {
		msm_rng_dev->fips140_drbg_enabled = FIPS140_DRBG_DISABLED;
		_fips_drbg_init_error(msm_rng_dev);
	}

	return ret;
}
#else
int _do_msm_fips_drbg_init(void *rng_dev)
{
	return 0;
}
#endif

#ifdef CONFIG_FIPS_ENABLE
static int _do_msm_rng_read(struct msm_rng_device *msm_rng_dev, void *data,
				size_t max)
{
	int sizeread=0;

	if (!msm_rng_dev) {
		qdrbg_m_pr_err("%s: msm_rng_device is null!\n", __func__);
		return 0;
	}

	if (0 == max) {
		/* Zero length requested. This is a no-op */
		return 0;
	}

	switch (fips_mode_enabled) {
	case FIPS140_DRBG_STARTED:
		sizeread = msm_rng_drbg_read(msm_rng_dev, data, max);
		break;
	case FIPS140_NOT_STARTED:
		sizeread = msm_rng_direct_read(msm_rng_dev, data, max);
		break;
	default:
		sizeread = 0;
		break;
	}

	return sizeread;
}
#endif
static int msm_rng_read(struct hwrng *rng,
			void *data,
			size_t max,
			bool wait)
{
	struct msm_rng_device *msm_rng_dev;
	int rv = 0;

	msm_rng_dev = (struct msm_rng_device *)rng->priv;

	mutex_lock(&cached_rng_lock);
	if (IS_ENABLED(CONFIG_FIPS_ENABLE))
		rv = _do_msm_rng_read(msm_rng_dev, data, max);
	else
		rv = msm_rng_direct_read(msm_rng_dev, data, max);
	mutex_unlock(&cached_rng_lock);

	return rv;
}

static struct hwrng msm_rng = {
	.name = DRIVER_NAME,
	.read = msm_rng_read,
};

static int msm_rng_enable_hw(struct msm_rng_device *msm_rng_dev)
{
	unsigned long val = 0;
	unsigned long reg_val = 0;
	int ret = 0;

	if (msm_rng_dev->qrng_perf_client) {
		ret = qdrbg_i_msm_bus_scale_client_update_request(
				msm_rng_dev->qrng_perf_client, 1);
		if (ret)
			qdrbg_m_pr_err("bus_scale_client_update_req err\n");
	}
	/* Enable the PRNG CLK */
	ret = qdrbg_i_clk_prepare_enable(msm_rng_dev->prng_clk);
	if (ret) {
		qdrbg_m_dev_err(&(msm_rng_dev->pdev)->dev,
				"failed to enable clock in probe\n");
		return -EPERM;
	}
	/* Enable PRNG h/w only if it is NOT ON */
	val = qdrbg_m_readl_relaxed(
		msm_rng_dev->base + PRNG_CONFIG_OFFSET) & PRNG_HW_ENABLE;
	/* PRNG H/W is not ON */
	if (val != PRNG_HW_ENABLE) {
		val = qdrbg_m_readl_relaxed(
			msm_rng_dev->base + PRNG_LFSR_CFG_OFFSET);
		val &= PRNG_LFSR_CFG_MASK;
		val |= PRNG_LFSR_CFG_CLOCKS;
		qdrbg_m_writel_relaxed(val,
			msm_rng_dev->base + PRNG_LFSR_CFG_OFFSET);

		/* The PRNG CONFIG register should be first written */
		qdrbg_m_mb();

		reg_val = qdrbg_m_readl_relaxed(
				msm_rng_dev->base + PRNG_CONFIG_OFFSET)
				& PRNG_CONFIG_MASK;
		reg_val |= PRNG_HW_ENABLE;
		qdrbg_m_writel_relaxed(reg_val,
				msm_rng_dev->base + PRNG_CONFIG_OFFSET);

		/* The PRNG clk should be disabled only after we enable the
		* PRNG h/w by writing to the PRNG CONFIG register.
		*/
		qdrbg_m_mb();
	}
	clk_disable_unprepare(msm_rng_dev->prng_clk);

	if (msm_rng_dev->qrng_perf_client) {
		ret = qdrbg_i_msm_bus_scale_client_update_request(
				msm_rng_dev->qrng_perf_client, 0);
		if (ret)
			pr_err("bus_scale_client_update_req failed!\n");
	}

	return 0;
}

static const struct file_operations msm_rng_fops = {
	.unlocked_ioctl = msm_rng_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_msm_rng_ioctl,
#endif
};

static struct class *msm_rng_class;
static struct cdev msm_rng_cdev;

#ifdef CONFIG_FIPS_ENABLE

static void _first_msm_drbg_init(struct msm_rng_device *msm_rng_dev)
{
	printk("in FIPS mode _first_msm_drbg_init\n");
	sp_msm_rng_dev = msm_rng_dev;
	return;
}
#else
static void _first_msm_drbg_init(struct msm_rng_device *msm_rng_dev)
{
	printk("in non-FIPS mode _first_msm_drbg_init\n");
	_do_msm_fips_drbg_init(msm_rng_dev);
}
#endif

static struct of_device_id qrng_match[] = {
	{.compatible = "qcom,msm-rng",},
	{}
};

static int msm_rng_probe(struct platform_device *pdev);
static int msm_rng_remove(struct platform_device *pdev);

static struct platform_driver rng_driver = {
	.probe	= msm_rng_probe,
	.remove	= msm_rng_remove,
	.driver	= {
		.name	= DRIVER_NAME,
		.owner	= NULL,
		.of_match_table = qrng_match,
	}
};

static int msm_rng_probe(struct platform_device *pdev)
{
	struct resource *res;
	struct msm_rng_device *msm_rng_dev = NULL;
	void __iomem *base = NULL;
	int error = 0;
	int ret = 0;
	struct device *dev;

	struct msm_bus_scale_pdata *qrng_platform_support = NULL;

	printk("In msm_rng_probe\n");

	res = qdrbg_platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (res == NULL) {
		qdrbg_m_dev_err(&pdev->dev, "invalid address\n");
		error = -EFAULT;
		goto err_exit;
	}

	msm_rng_dev = qdrbg_i_kzalloc(sizeof(struct msm_rng_device),
					GFP_KERNEL);
	if (!msm_rng_dev) {
		qdrbg_m_dev_err(&pdev->dev, "cannot allocate memory\n");
		error = -ENOMEM;
		goto err_exit;
	}

	base = qdrbg_i_ioremap(res->start, resource_size(res));
	if (!base) {
		qdrbg_m_dev_err(&pdev->dev, "ioremap failed\n");
		error = -ENOMEM;
		goto err_iomap;
	}
	msm_rng_dev->base = base;

	msm_rng_dev->drbg_ctx = qdrbg_i_kzalloc(
					sizeof(struct fips_drbg_ctx_s),
					GFP_KERNEL);
	if (!msm_rng_dev->drbg_ctx) {
		qdrbg_m_dev_err(&pdev->dev, "cannot allocate memory\n");
		error = -ENOMEM;
		goto err_clk_get;
	}

	/* create a handle for clock control */
	if ((pdev->dev.of_node) && (of_property_read_bool(pdev->dev.of_node,
					"qcom,msm-rng-iface-clk")))
		msm_rng_dev->prng_clk = qdrbg_clk_get(&pdev->dev,
							"iface_clk");
	else
		msm_rng_dev->prng_clk = qdrbg_clk_get(&pdev->dev,
							"core_clk");

	if (qdrbg_i_IS_ERR(msm_rng_dev->prng_clk)) {
		qdrbg_m_dev_err(&pdev->dev, "failed to register clock\n");
		error = -EPERM;
		goto err_clk_get;
	}

	/* save away pdev and register driver data */
	msm_rng_dev->pdev = pdev;
	qdrbg_i_platform_set_drvdata(pdev, msm_rng_dev);
	if (pdev->dev.of_node) {
		/* Register bus client */
		qrng_platform_support = qdrbg_i_msm_bus_cl_get_pdata(pdev);
		msm_rng_dev->qrng_perf_client =
				qdrbg_i_msm_bus_scale_register_client(
					qrng_platform_support);
		msm_rng_device_info.qrng_perf_client =
					msm_rng_dev->qrng_perf_client;
		if (!msm_rng_dev->qrng_perf_client)
			pr_err("Unable to register bus client\n");
	}

	/* Enable rng h/w */
	error = msm_rng_enable_hw(msm_rng_dev);

	if (error)
		goto rollback_clk;

	mutex_init(&msm_rng_dev->rng_lock);
	mutex_init(&cached_rng_lock);

	/* register with hwrng framework */
	msm_rng.priv = (unsigned long) msm_rng_dev;
	error = qdrbg_hwrng_register(&msm_rng);
	if (error) {
		qdrbg_m_dev_err(&pdev->dev, "failed to register hwrng\n");
		error = -EPERM;
		goto rollback_clk;
	}
	ret = qdrbg_i_register_chrdev(QRNG_IOC_MAGIC,
					DRIVER_NAME,
					&msm_rng_fops);

	msm_rng_class = qdrbg_m_class_create(rng_driver.driver.owner,
						"msm-rng");
	if (qdrbg_i_IS_ERR(msm_rng_class)) {
		qdrbg_m_pr_err("class_create failed\n");
		return qdrbg_i_PTR_ERR(msm_rng_class);
	}

	dev = qdrbg_device_create(msm_rng_class,
				NULL,
				MKDEV(QRNG_IOC_MAGIC, 0),
				NULL,
				"msm-rng");
	if (qdrbg_i_IS_ERR(dev)) {
		qdrbg_m_pr_err("Device create failed\n");
		error = qdrbg_i_PTR_ERR(dev);
		goto unregister_chrdev;
	}
	qdrbg_cdev_init(&msm_rng_cdev, &msm_rng_fops);

	_first_msm_drbg_init(msm_rng_dev);

	msm_rng_dev_cached = msm_rng_dev;
	return error;

unregister_chrdev:
	qdrbg_i_unregister_chrdev(QRNG_IOC_MAGIC, DRIVER_NAME);
rollback_clk:
	qdrbg_clk_put(msm_rng_dev->prng_clk);
err_clk_get:
	qdrbg_i_iounmap(msm_rng_dev->base);
err_iomap:
	qdrbg_kzfree(msm_rng_dev->drbg_ctx);
	qdrbg_kzfree(msm_rng_dev);
err_exit:
	return error;
}

static int msm_rng_remove(struct platform_device *pdev)
{
	struct msm_rng_device *msm_rng_dev =
				qdrbg_i_platform_get_drvdata(pdev);

	mutex_lock(&cached_rng_lock);
	qdrbg_i_unregister_chrdev(QRNG_IOC_MAGIC, DRIVER_NAME);
	qdrbg_hwrng_unregister(&msm_rng);
	qdrbg_clk_put(msm_rng_dev->prng_clk);
	qdrbg_i_iounmap(msm_rng_dev->base);
	qdrbg_i_platform_set_drvdata(pdev, NULL);
	if (msm_rng_dev->qrng_perf_client)
		qdrbg_i_msm_bus_scale_unregister_client(
					msm_rng_dev->qrng_perf_client);
	if (msm_rng_dev->drbg_ctx) {
		fips_drbg_final(msm_rng_dev->drbg_ctx);
		qdrbg_kzfree(msm_rng_dev->drbg_ctx);
		msm_rng_dev->drbg_ctx = NULL;
	}
	qdrbg_kzfree(msm_rng_dev);
	msm_rng_dev_cached = NULL;
	mutex_unlock(&cached_rng_lock);
	return 0;
}

static int qrng_get_random(struct crypto_rng *tfm, u8 *rdata,
                            unsigned int dlen)
{
	int sizeread = 0;
	int rv = -EFAULT;

	if (!msm_rng_dev_cached) {
		qdrbg_m_pr_err("%s: msm_rng_dev is not initialized.\n", __func__);
		rv = -ENODEV;
		goto err_exit;
	}

	if (!rdata) {
                qdrbg_m_pr_err("%s: data buffer is null!\n", __func__);
                rv = -EINVAL;
		goto err_exit;
        }

        if (signal_pending(current) ||
                mutex_lock_interruptible(&cached_rng_lock)) {
                qdrbg_m_pr_err("%s: mutex lock interrupted!\n", __func__);
                rv = -ERESTARTSYS;
                goto err_exit;
        }
        sizeread = _do_msm_rng_read(msm_rng_dev_cached, rdata, dlen);

	if (sizeread == dlen)
		rv = 0;

	mutex_unlock(&cached_rng_lock);
err_exit:
	return rv;

}

static int qrng_reset(struct crypto_rng *tfm, u8 *seed, unsigned int slen)
{
	return 0;
}

static struct crypto_alg rng_alg = {
        .cra_name               = "qrng",
        .cra_driver_name        = "fips_qrng",
        .cra_priority           = 300,
        .cra_flags              = CRYPTO_ALG_TYPE_RNG,
        .cra_ctxsize            = 0,
        .cra_type               = &crypto_rng_type,
        .cra_module             = THIS_MODULE,
        .cra_u                  = {
                .rng = {
                        .rng_make_random        = qrng_get_random,
                        .rng_reset              = qrng_reset,
                        .seedsize = 0,
                }
        }
};


int do_msm_rng_init(struct module *msm_module)
{
	int ret;

	rng_driver.driver.owner = msm_module;

	ret = qdrbg_platform_driver_register(&rng_driver);
	if (ret) {
		qdrbg_m_pr_err("%s: platform_driver_register error:%d\n",
			__func__, ret);
		goto err_exit;
	}

	ret = crypto_register_alg(&rng_alg);
	if (ret) {
		qdrbg_m_pr_err("%s: crypto_register_algs error:%d\n",
			__func__, ret);
		goto err_exit;
	}

err_exit:
	return ret;
}

void do_msm_rng_exit(void)
{
	crypto_unregister_alg(&rng_alg);
	qdrbg_platform_driver_unregister(&rng_driver);
}

MODULE_DESCRIPTION("FIPS Compliant Random Number Generator");
MODULE_ALIAS("qrng");
MODULE_ALIAS("fips_qrng");
