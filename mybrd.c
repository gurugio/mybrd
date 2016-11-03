/*
 * Ram backed block device driver.
 *
 * Copyright (C) 2007 Nick Piggin
 * Copyright (C) 2007 Novell Inc.
 *
 * Parts derived from drivers/block/rd.c, and drivers/block/loop.c, copyright
 * of their respective owners.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>

#ifdef pr_warn
#undef pr_warn
#endif
#define pr_warn(fmt, arg...) printk(KERN_WARNING "mybrd: "fmt, ##arg)

MODULE_LICENSE("GPL");

static int mybrd_major;


static int __init mybrd_init(void)
{
	mybrd_major = register_blkdev(0, "my-ramdisk");
	if (mybrd_major < 0)
		return mybrd_major;
	pr_warn("mybrd major=%d\n", mybrd_major);

	pr_warn("\n\n\nmybrd: module loaded\n\n\n\n");
	return 0;
}

static void __exit mybrd_exit(void)
{
	unregister_blkdev(mybrd_major, "my-ramdisk");
	pr_warn("brd: module unloaded\n");
}

module_init(mybrd_init);
module_exit(mybrd_exit);

