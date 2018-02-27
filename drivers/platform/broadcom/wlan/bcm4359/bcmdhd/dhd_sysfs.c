/*
 * dhd_sysfs.c - various sysfs bcmdhd control interfaces
 *
 *      Author: Ji Huang <cocafehj@gmail.com>
 *
 *      Note: Due to bcmdhd driver is very complex, this file insert 
 *            into dhd_linux.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 */

#include <linux/kobject.h>

static dhd_info_t *dhd_info_p;

enum DHD_IOCTL_OP {
	DHD_IOCTL_OP_NONE = 0,
	DHD_IOCTL_OP_GET,
	DHD_IOCTL_OP_SET,
};

static int dhd_ioctl_last_op = DHD_IOCTL_OP_NONE;
static int dhd_ioctl_last_cmd;
static int dhd_ioctl_last_val;

static ssize_t dhd_ioctl_show(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   char *buf)
{
	int ret;

	switch (dhd_ioctl_last_op) {
		case DHD_IOCTL_OP_GET:
			ret = dhd_wl_ioctl_cmd(&dhd_info_p->pub,
			                       dhd_ioctl_last_cmd,
			                       &dhd_ioctl_last_val,
			                       sizeof(dhd_ioctl_last_val),
			                       FALSE,
			                       0);
			if (ret) {
				pr_err("%s: failed to get ioctl cmd\n", __func__);
				return -EIO;
			}

			return sprintf(buf, "%d\n", dhd_ioctl_last_val);

		case DHD_IOCTL_OP_SET:
		case DHD_IOCTL_OP_NONE:
		default:
			return -ENODATA;
	}
}

static ssize_t dhd_ioctl_store(struct kobject *kobj,
                                    struct kobj_attribute *attr,
                                    const char *buf,
                                    size_t count)
{
	int cmd;
	int val;
	int ret;

	if (sscanf(buf, "set %d %d", &cmd, &val) == 2) {
		dhd_ioctl_last_op = DHD_IOCTL_OP_SET;

		ret = dhd_wl_ioctl_cmd(&dhd_info_p->pub, cmd, &val, sizeof(val), TRUE, 0);
		if (ret) {
			pr_err("%s: failed to set ioctl cmd\n", __func__);
			return -EIO;
		}
	} else if (sscanf(buf, "get %d", &cmd) == 1) {
		dhd_ioctl_last_op = DHD_IOCTL_OP_GET;

		ret = dhd_wl_ioctl_cmd(&dhd_info_p->pub, cmd, &val, sizeof(val), FALSE, 0);
		if (ret) {
			pr_err("%s: failed to get ioctl cmd\n", __func__);
			return -EIO;
		}

		dhd_ioctl_last_cmd = cmd;
		dhd_ioctl_last_val = val;
	} else {
		return -EINVAL;
	}

	return count;
}

static struct kobj_attribute dhd_ioctl_interface =
	__ATTR(ioctl, 0600, dhd_ioctl_show, dhd_ioctl_store);

#if defined(DHD_TRACE_WAKE_LOCK)
extern int trace_wklock_onoff;

static ssize_t wakelock_trace_show(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   char *buf)
{
	sprintf(buf, "%d\n", trace_wklock_onoff);
	dhd_wk_lock_stats_dump(&dhd_info_p->pub);

	return strlen(buf);
}

static ssize_t wakelock_trace_store(struct kobject *kobj,
                                    struct kobj_attribute *attr,
                                    const char *buf,
                                    size_t count)
{
	size_t val;
	unsigned long flags;

	if (sscanf(buf, "%zu", &val) != 1) {
		return -EINVAL;
	}

	spin_lock_irqsave(&dhd_info_p->wakelock_spinlock, flags);
	trace_wklock_onoff = !!val;
	spin_unlock_irqrestore(&dhd_info_p->wakelock_spinlock, flags);

	pr_info("%s(): trace_wklock_onoff: %d",
	          __func__, trace_wklock_onoff);

	return count;
}

static struct kobj_attribute wakelock_trace_interface =
	__ATTR(wakelock_trace, 0600, wakelock_trace_show, wakelock_trace_store);

#endif /* DHD_TRACE_WAKE_LOCK */

static struct attribute *dhd_attrs[] = {
	&dhd_ioctl_interface.attr,
#if defined(DHD_TRACE_WAKE_LOCK)
	&wakelock_trace_interface.attr,
#endif /* DHD_TRACE_WAKE_LOCK */
	NULL,
};

static struct attribute_group dhd_interface_group = {
	// .name  = "bcmdhd", // name to make sub folder
	.attrs = dhd_attrs,
};

static struct kobject *dhd_kobject;

static void dhd_register_dev(dhd_info_t *dhd)
{
	dhd_info_p = dhd;
}

static int dhd_sysfs_init(dhd_info_t *dhd)
{
	int ret = -1;

	if (dhd == NULL) {
		DHD_ERROR(("%s(): dhd is NULL\n", __func__));
		return ret;
	}

	dhd_register_dev(dhd);

	dhd_kobject = kobject_create_and_add("bcmdhd", kernel_kobj);
	if (!dhd_kobject) {
		DHD_ERROR(("%s(): Failed to create kobject interface\n", __func__));
		return -EIO;
	}

	ret = sysfs_create_group(dhd_kobject, &dhd_interface_group);
	if (ret) {
		DHD_ERROR(("%s(): Failed to create sysfs kobject interface\n", __func__));
		kobject_put(dhd_kobject);
	}

        return ret;
}

static void dhd_sysfs_exit(dhd_info_t *dhd)
{
	if (dhd == NULL) {
		DHD_ERROR(("%s(): dhd is NULL\n", __func__));
		return;
	}

	kobject_put(dhd_kobject);
}
