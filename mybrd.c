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
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/radix-tree.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/blk-mq.h>
#include <linux/nodemask.h>

#ifdef pr_warn
#undef pr_warn
#endif
#define pr_warn(fmt, arg...) printk(KERN_WARNING "mybrd: "fmt, ##arg)

MODULE_LICENSE("GPL");


struct mybrd_device {
	struct request_queue *mybrd_queue;
	struct gendisk *mybrd_disk;
	spinlock_t mybrd_lock;
};


static int mybrd_major;
struct mybrd_device *global_mybrd;
#define MYBRD_SIZE_4M 4*1024*1024


static int mybrd_ioctl(struct block_device *bdev, fmode_t mode,
			unsigned int cmd, unsigned long arg)
{
	int error = 0;
	pr_warn("start mybrd_ioctl\n");

	pr_warn("end mybrd_ioctl\n");
	return error;
}

static const struct block_device_operations mybrd_fops = {
	.owner =		THIS_MODULE,
	.ioctl =		mybrd_ioctl,
};

static blk_qc_t mybrd_make_request_fn(struct request_queue *q, struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;
	struct mybrd_device *mybrd = bdev->bd_disk->private_data;
	int rw;
	struct bio_vec bvec;
	sector_t sector;
	sector_t end_sector;
	struct bvec_iter iter;
	unsigned long start_time = jiffies;

	pr_warn("start mybrd_make_request_fn: block_device=%p mybrd=%p\n",
		bdev, mybrd);
	//dump_stack();

	if (mybrd != global_mybrd)
		goto io_error;

	sector = bio->bi_iter.bi_sector;
	end_sector = bio_end_sector(bio);
	rw = bio_rw(bio);
	pr_warn("bio-info: sector=%d end_sector=%d rw=%s\n",
		(int)sector, (int)end_sector, rw == READ ? "READ" : "WRITE");
	pr_warn("bio-info: end-io=%p\n", bio->bi_end_io);

	generic_start_io_acct(rw, bio_sectors(bio), &mybrd->mybrd_disk->part0);

	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		struct page *p = bvec.bv_page;
		unsigned int offset = bvec.bv_offset;

		pr_warn("segment-info: len=%u p=%p offset=%u\n",
			len, p, offset);

	}
		
	bio_endio(bio);

	generic_end_io_acct(rw, &mybrd->mybrd_disk->part0, start_time);
	
	pr_warn("end mybrd_make_request\n");
	// no cookie
	return BLK_QC_T_NONE;
io_error:
	bio_io_error(bio);
	return BLK_QC_T_NONE;
}

static struct mybrd_device *mybrd_alloc(void)
{
	struct mybrd_device *mybrd;
	struct request_queue *rq;
	struct gendisk *disk;

	pr_warn("start mybrd_alloc\n");

	/*
	 * 1st: mybrd_device object
	 */
	mybrd = kzalloc(sizeof(*mybrd), GFP_KERNEL);
	if (!mybrd)
		goto out;

	spin_lock_init(&mybrd->mybrd_lock);
	pr_warn("create mybrd:%p\n", mybrd);

	/*
	 * 2nd: request-queue object
	 */
	rq = mybrd->mybrd_queue = blk_alloc_queue_node(GFP_KERNEL, NUMA_NO_NODE);
	if (!rq)
		goto out_free_brd;

	blk_queue_make_request(rq, mybrd_make_request_fn);
	rq->queuedata = mybrd;
	blk_queue_max_hw_sectors(rq, 1024);
	blk_queue_bounce_limit(rq, BLK_BOUNCE_ANY);
	blk_queue_physical_block_size(rq, PAGE_SIZE);
	blk_queue_logical_block_size(rq, PAGE_SIZE);
	rq->limits.discard_granularity = PAGE_SIZE;
	blk_queue_max_discard_sectors(rq, UINT_MAX);
	rq->limits.discard_zeroes_data = 1;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, rq);

	/*
	 * 3rd: gendisk object
	 */
	disk = mybrd->mybrd_disk = alloc_disk(1);
	if (!disk)
		goto out_free_queue;

	disk->major = mybrd_major;
	disk->first_minor = 111;
	disk->fops = &mybrd_fops;
	disk->private_data = mybrd;
	disk->queue = rq;
	disk->flags = GENHD_FL_EXT_DEVT;
	strncpy(disk->disk_name, "mybrd", strlen("mybrd"));
	set_capacity(disk, MYBRD_SIZE_4M >> 9);

	// start IO
	add_disk(disk);
	pr_warn("end mybrd_alloc\n");
	
	return mybrd;

out_free_queue:
	blk_cleanup_queue(rq);
out_free_brd:
	kfree(mybrd);
out:
	return NULL;
}

static void mybrd_free(struct mybrd_device *mybrd)
{
	blk_cleanup_queue(mybrd->mybrd_queue);
	kfree(mybrd);
}

static int __init mybrd_init(void)
{
	pr_warn("\n\n\nmybrd: module loaded\n\n\n\n");

	mybrd_major = register_blkdev(mybrd_major, "my-ramdisk");
	if (mybrd_major < 0)
		return mybrd_major;

	pr_warn("mybrd major=%d\n", mybrd_major);
	global_mybrd = mybrd_alloc();
	if (!global_mybrd) {
		pr_warn("failed to initialize mybrd\n");
		unregister_blkdev(mybrd_major, "my-ramdisk");
		return -1;
	}
	pr_warn("global-mybrd=%p\n", global_mybrd);

	return 0;
}

static void __exit mybrd_exit(void)
{
	mybrd_free(global_mybrd);
	unregister_blkdev(mybrd_major, "my-ramdisk");
	
	pr_warn("brd: module unloaded\n");
}

module_init(mybrd_init);
module_exit(mybrd_exit);

