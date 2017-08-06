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
	{ 0x9a908b80, __VMLINUX_SYMBOL_STR(test_and_clear_bit) },
	{ 0xf9a482f9, __VMLINUX_SYMBOL_STR(msleep) },
	{ 0x79fa08e9, __VMLINUX_SYMBOL_STR(bluesleep_stop) },
	{ 0x5de95b3d, __VMLINUX_SYMBOL_STR(mutex_destroy) },
	{ 0x98cf60b3, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x600d676a, __VMLINUX_SYMBOL_STR(dev_set_drvdata) },
	{ 0x20000329, __VMLINUX_SYMBOL_STR(simple_strtoul) },
	{ 0x8d9bb302, __VMLINUX_SYMBOL_STR(mutex_unlock) },
	{ 0x85df9b6c, __VMLINUX_SYMBOL_STR(strsep) },
	{ 0xa87cf413, __VMLINUX_SYMBOL_STR(clear_bit) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0x27fb862f, __VMLINUX_SYMBOL_STR(sysfs_remove_group) },
	{ 0x7d11c268, __VMLINUX_SYMBOL_STR(jiffies) },
	{ 0xa120d33c, __VMLINUX_SYMBOL_STR(tty_unregister_ldisc) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0xb61a0c3b, __VMLINUX_SYMBOL_STR(bt_err) },
	{ 0x86ea4d38, __VMLINUX_SYMBOL_STR(complete_all) },
	{ 0xab40cca9, __VMLINUX_SYMBOL_STR(__init_waitqueue_head) },
	{ 0x6d340f64, __VMLINUX_SYMBOL_STR(tty_termios_input_baud_rate) },
	{ 0x4b2bd1d9, __VMLINUX_SYMBOL_STR(skb_queue_purge) },
	{ 0xd3259d65, __VMLINUX_SYMBOL_STR(test_and_set_bit) },
	{ 0xdcb764ad, __VMLINUX_SYMBOL_STR(memset) },
	{ 0x97fdbab9, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_irqrestore) },
	{ 0x427ec3d8, __VMLINUX_SYMBOL_STR(__mutex_init) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x20c55ae0, __VMLINUX_SYMBOL_STR(sscanf) },
	{ 0x3c220f1a, __VMLINUX_SYMBOL_STR(sysfs_create_group) },
	{ 0x5f456654, __VMLINUX_SYMBOL_STR(tty_ldisc_flush) },
	{ 0xbd447ecf, __VMLINUX_SYMBOL_STR(netlink_kernel_release) },
	{ 0xd632567a, __VMLINUX_SYMBOL_STR(n_tty_ioctl_helper) },
	{ 0x32e71db, __VMLINUX_SYMBOL_STR(bluesleep_start) },
	{ 0x9166fada, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0x5a921311, __VMLINUX_SYMBOL_STR(strncmp) },
	{ 0xf268bbf9, __VMLINUX_SYMBOL_STR(skb_push) },
	{ 0x2dffc6fb, __VMLINUX_SYMBOL_STR(mutex_lock) },
	{ 0xfe84fcc8, __VMLINUX_SYMBOL_STR(netlink_unicast) },
	{ 0xefa5791, __VMLINUX_SYMBOL_STR(platform_driver_register) },
	{ 0x97c8dc87, __VMLINUX_SYMBOL_STR(skb_pull) },
	{ 0xa7fa1971, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0x434030f0, __VMLINUX_SYMBOL_STR(skb_queue_tail) },
	{ 0x6947613e, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0x4c62f45b, __VMLINUX_SYMBOL_STR(tty_driver_flush_buffer) },
	{ 0xf0fdf6cb, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x3bd1b1f6, __VMLINUX_SYMBOL_STR(msecs_to_jiffies) },
	{ 0x26ea76f2, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0x8de2b83f, __VMLINUX_SYMBOL_STR(sysfs_notify) },
	{ 0x692f878e, __VMLINUX_SYMBOL_STR(stop_tty) },
	{ 0xa6c87651, __VMLINUX_SYMBOL_STR(bluesleep_outgoing_data) },
	{ 0x79e41933, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x96220280, __VMLINUX_SYMBOL_STR(_raw_spin_lock_irqsave) },
	{ 0x409873e3, __VMLINUX_SYMBOL_STR(tty_termios_baud_rate) },
	{ 0x9853f687, __VMLINUX_SYMBOL_STR(__netlink_kernel_create) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x4829a47e, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0xae8c4d0c, __VMLINUX_SYMBOL_STR(set_bit) },
	{ 0x28ea791e, __VMLINUX_SYMBOL_STR(request_firmware) },
	{ 0xe36ac5be, __VMLINUX_SYMBOL_STR(skb_dequeue) },
	{ 0x8f678b07, __VMLINUX_SYMBOL_STR(__stack_chk_guard) },
	{ 0xbdbc13a1, __VMLINUX_SYMBOL_STR(complete) },
	{ 0xbbedfff2, __VMLINUX_SYMBOL_STR(platform_driver_unregister) },
	{ 0xdd038843, __VMLINUX_SYMBOL_STR(tty_register_ldisc) },
	{ 0xed47874b, __VMLINUX_SYMBOL_STR(skb_put) },
	{ 0xf3a426a4, __VMLINUX_SYMBOL_STR(wait_for_completion_timeout) },
	{ 0x65949abd, __VMLINUX_SYMBOL_STR(__nlmsg_put) },
	{ 0x5b67ce10, __VMLINUX_SYMBOL_STR(dev_get_drvdata) },
	{ 0xa8aeef24, __VMLINUX_SYMBOL_STR(release_firmware) },
	{ 0x4dc1f21b, __VMLINUX_SYMBOL_STR(tty_set_termios) },
	{ 0xe914e41e, __VMLINUX_SYMBOL_STR(strcpy) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "3F536C5805F3BE4C1B15A31");
