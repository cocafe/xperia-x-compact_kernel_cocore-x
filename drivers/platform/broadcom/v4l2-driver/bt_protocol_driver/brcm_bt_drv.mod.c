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
	{ 0x15692c87, __VMLINUX_SYMBOL_STR(param_ops_int) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0xc800e96c, __VMLINUX_SYMBOL_STR(cdev_del) },
	{ 0x8c03d20c, __VMLINUX_SYMBOL_STR(destroy_workqueue) },
	{ 0x43a53735, __VMLINUX_SYMBOL_STR(__alloc_workqueue_key) },
	{ 0x69d8c987, __VMLINUX_SYMBOL_STR(device_destroy) },
	{ 0x8650a42b, __VMLINUX_SYMBOL_STR(cdev_add) },
	{ 0x94b273e3, __VMLINUX_SYMBOL_STR(cdev_init) },
	{ 0x7485e15e, __VMLINUX_SYMBOL_STR(unregister_chrdev_region) },
	{ 0xef038a, __VMLINUX_SYMBOL_STR(class_destroy) },
	{ 0x5abf916b, __VMLINUX_SYMBOL_STR(device_create) },
	{ 0xd023a2a8, __VMLINUX_SYMBOL_STR(__class_create) },
	{ 0x79e41933, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x9ed5c2ca, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x29537c9e, __VMLINUX_SYMBOL_STR(alloc_chrdev_region) },
	{ 0x65345022, __VMLINUX_SYMBOL_STR(__wake_up) },
	{ 0x26ea76f2, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0xe36ac5be, __VMLINUX_SYMBOL_STR(skb_dequeue) },
	{ 0x67c2fa54, __VMLINUX_SYMBOL_STR(__copy_to_user) },
	{ 0x2e0d2f7f, __VMLINUX_SYMBOL_STR(queue_work_on) },
	{ 0x434030f0, __VMLINUX_SYMBOL_STR(skb_queue_tail) },
	{ 0xdcb764ad, __VMLINUX_SYMBOL_STR(memset) },
	{ 0xfbc74f64, __VMLINUX_SYMBOL_STR(__copy_from_user) },
	{ 0xed47874b, __VMLINUX_SYMBOL_STR(skb_put) },
	{ 0x6947613e, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0x7d11c268, __VMLINUX_SYMBOL_STR(jiffies) },
	{ 0xf3a426a4, __VMLINUX_SYMBOL_STR(wait_for_completion_timeout) },
	{ 0x3bd1b1f6, __VMLINUX_SYMBOL_STR(msecs_to_jiffies) },
	{ 0xab40cca9, __VMLINUX_SYMBOL_STR(__init_waitqueue_head) },
	{ 0x5abb2113, __VMLINUX_SYMBOL_STR(brcm_sh_ldisc_register) },
	{ 0x97fdbab9, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_irqrestore) },
	{ 0x96220280, __VMLINUX_SYMBOL_STR(_raw_spin_lock_irqsave) },
	{ 0x4b2bd1d9, __VMLINUX_SYMBOL_STR(skb_queue_purge) },
	{ 0xa87cf413, __VMLINUX_SYMBOL_STR(clear_bit) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xcd7f99eb, __VMLINUX_SYMBOL_STR(brcm_sh_ldisc_unregister) },
	{ 0x9a908b80, __VMLINUX_SYMBOL_STR(test_and_clear_bit) },
	{ 0x88bfa7e, __VMLINUX_SYMBOL_STR(cancel_work_sync) },
	{ 0xae8c4d0c, __VMLINUX_SYMBOL_STR(set_bit) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=brcm_hci_ldisc";


MODULE_INFO(srcversion, "772EFCBA43AAA979BEC939A");
