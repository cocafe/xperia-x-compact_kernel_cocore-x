#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

MODULE_INFO(intree, "Y");

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xee56164b, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x9ed5c2ca, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0x15692c87, __VMLINUX_SYMBOL_STR(param_ops_int) },
	{ 0x67c2fa54, __VMLINUX_SYMBOL_STR(__copy_to_user) },
	{ 0x98cf60b3, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x600d676a, __VMLINUX_SYMBOL_STR(dev_set_drvdata) },
	{ 0x43a53735, __VMLINUX_SYMBOL_STR(__alloc_workqueue_key) },
	{ 0xc8b57c27, __VMLINUX_SYMBOL_STR(autoremove_wake_function) },
	{ 0x963f7b35, __VMLINUX_SYMBOL_STR(video_device_release) },
	{ 0x88bfa7e, __VMLINUX_SYMBOL_STR(cancel_work_sync) },
	{ 0xeae3dfd6, __VMLINUX_SYMBOL_STR(__const_udelay) },
	{ 0xf12fc4cb, __VMLINUX_SYMBOL_STR(__video_register_device) },
	{ 0xa87cf413, __VMLINUX_SYMBOL_STR(clear_bit) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0x27fb862f, __VMLINUX_SYMBOL_STR(sysfs_remove_group) },
	{ 0x7d11c268, __VMLINUX_SYMBOL_STR(jiffies) },
	{ 0xab40cca9, __VMLINUX_SYMBOL_STR(__init_waitqueue_head) },
	{ 0x5abb2113, __VMLINUX_SYMBOL_STR(brcm_sh_ldisc_register) },
	{ 0x4b2bd1d9, __VMLINUX_SYMBOL_STR(skb_queue_purge) },
	{ 0x60ea2d6, __VMLINUX_SYMBOL_STR(kstrtoull) },
	{ 0xdcb764ad, __VMLINUX_SYMBOL_STR(memset) },
	{ 0xca378f7f, __VMLINUX_SYMBOL_STR(video_device_alloc) },
	{ 0xcd7f99eb, __VMLINUX_SYMBOL_STR(brcm_sh_ldisc_unregister) },
	{ 0x97fdbab9, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_irqrestore) },
	{ 0x37befc70, __VMLINUX_SYMBOL_STR(jiffies_to_msecs) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x3c220f1a, __VMLINUX_SYMBOL_STR(sysfs_create_group) },
	{ 0x20056c9, __VMLINUX_SYMBOL_STR(video_unregister_device) },
	{ 0x5a921311, __VMLINUX_SYMBOL_STR(strncmp) },
	{ 0x5792f848, __VMLINUX_SYMBOL_STR(strlcpy) },
	{ 0xf268bbf9, __VMLINUX_SYMBOL_STR(skb_push) },
	{ 0x8c03d20c, __VMLINUX_SYMBOL_STR(destroy_workqueue) },
	{ 0x97c8dc87, __VMLINUX_SYMBOL_STR(skb_pull) },
	{ 0x434030f0, __VMLINUX_SYMBOL_STR(skb_queue_tail) },
	{ 0x6947613e, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0xf0c1d961, __VMLINUX_SYMBOL_STR(video_devdata) },
	{ 0x1000e51, __VMLINUX_SYMBOL_STR(schedule) },
	{ 0x26ea76f2, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0x79e41933, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x96220280, __VMLINUX_SYMBOL_STR(_raw_spin_lock_irqsave) },
	{ 0xadb5559d, __VMLINUX_SYMBOL_STR(param_ops_byte) },
	{ 0x65345022, __VMLINUX_SYMBOL_STR(__wake_up) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x4829a47e, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x1bca2a90, __VMLINUX_SYMBOL_STR(prepare_to_wait) },
	{ 0xae8c4d0c, __VMLINUX_SYMBOL_STR(set_bit) },
	{ 0x9c5bc552, __VMLINUX_SYMBOL_STR(finish_wait) },
	{ 0xe36ac5be, __VMLINUX_SYMBOL_STR(skb_dequeue) },
	{ 0x2e0d2f7f, __VMLINUX_SYMBOL_STR(queue_work_on) },
	{ 0xbdbc13a1, __VMLINUX_SYMBOL_STR(complete) },
	{ 0xed47874b, __VMLINUX_SYMBOL_STR(skb_put) },
	{ 0xf3a426a4, __VMLINUX_SYMBOL_STR(wait_for_completion_timeout) },
	{ 0x6d044c26, __VMLINUX_SYMBOL_STR(param_ops_uint) },
	{ 0x5b67ce10, __VMLINUX_SYMBOL_STR(dev_get_drvdata) },
	{ 0xd00190eb, __VMLINUX_SYMBOL_STR(video_ioctl2) },
	{ 0xe914e41e, __VMLINUX_SYMBOL_STR(strcpy) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=brcm_hci_ldisc";


MODULE_INFO(srcversion, "8A65570B634B5E954207F0F");
