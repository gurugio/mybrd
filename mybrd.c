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

#ifdef pr_warn
#undef pr_warn
#endif
#define pr_warn(fmt, arg...) printk(KERN_WARNING "mybrd: "fmt, ##arg)

MODULE_LICENSE("GPL");


struct mybrd_device {
	int mybrd_number;

	struct request_queue *mybrd_queue;
	struct gendisk *mybrd_disk;

	spinlock_t mybrd_lock;
	struct radix_tree_root mybrd_pages;
};


static int mybrd_major;
struct mybrd_device *global_mybrd;
#define MYBRD_SIZE_SECT 1024*2 // 1k*2*512 = 1Mb	


static struct page *mybrd_lookup_page(struct mybrd_device *mybrd,
				      sector_t sector)
{
	pgoff_t idx;
	struct page *p;

	rcu_read_lock(); // why rcu-read-lock?

	// 9 = SECTOR_SHIFT
	idx = sector >> (PAGE_SHIFT - 9);
	page = radix_tree_lookup(&mybrd->mybrd_pages, idx);

	rcu_read_unlock();

	pr_warn("lookup-page: %d\n", page ? (int)page->index : -1);
	return page;
}

static struct page *mybrd_insert_page(struct mybrd_device *mybrd,
				      sector_t sector)
{

}

static blk_qc_t mybrd_make_request(struct request_queue *q, struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;
	struct mybrd_device *mybrd = bdev->bd_disk->private_data;
	int rw;
	struct bio_vec bvec;
	sector_t sector;
	sector_t end_sector;
	struct bvec_iter iter;

	pr_warn("start mybrd_make_request: block_device=%p mybrd=%p\n",
		bdev, mybrd);


	// add dump_stack()
	dump_stack();
	
	// print info of bio
	sector = bio->bi_iter.bi_sector;
	end_sector = bio_sectors(bio);
	rw = bio_rw(bio);
	pr_warn("bio-info: sector=%d end_sector=%d rw=%s\n",
		(int)sector, (int)end_sector, rw == READ ? "READ" : "WRITE");

	// ffffffff81187890 t end_bio_bh_io_sync
	pr_warn("bio-info: end-io=%p\n", bio->bi_end_io);


	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		struct page *p = bvec.bv_page;
		unsigned int offset = bvec.bv_offset;

		pr_warn("bio-info: len=%u p=%p offset=%u\n",
			len, p, offset);
	}
		
	
	// when disk is added, make_request is called..why??
	
	bio_endio(bio);
	
	pr_warn("end mybrd_make_request");
	// no cookie
	return BLK_QC_T_NONE;
}


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

static struct mybrd_device *mybrd_alloc(void)
{
	struct mybrd_device *mybrd;
	struct gendisk *disk;

	pr_warn("start mybrd_alloc\n");
	mybrd = kzalloc(sizeof(*mybrd), GFP_KERNEL);
	if (!mybrd)
		goto out;

	mybrd->mybrd_number = 0;
	
	spin_lock_init(&mybrd->mybrd_lock);
	INIT_RADIX_TREE(&mybrd->mybrd_pages, GFP_ATOMIC);

	
	// null_blk uses blk_alloc_queue_node()
	pr_warn("create mybrd->mybrd_queue\n");
	mybrd->mybrd_queue = blk_alloc_queue_node(GFP_KERNEL, NUMA_NO_NODE);
	if (!mybrd->mybrd_queue)
		goto out_free_brd;

	blk_queue_make_request(mybrd->mybrd_queue, mybrd_make_request);
	// 1024*512 = 512K size?
	// null_blk does not set max-hw-sectors because there is no limit
	blk_queue_max_hw_sectors(mybrd->mybrd_queue, 1024);
	// don't know why
	blk_queue_bounce_limit(mybrd->mybrd_queue, BLK_BOUNCE_ANY);

	// ram disk can have 4K block
	// null_blk set 512b.. may be to simulate real device?
	blk_queue_physical_block_size(mybrd->mybrd_queue, PAGE_SIZE);

	// don't know why
	mybrd->mybrd_queue->limits.discard_granularity = PAGE_SIZE;

	// max sectors for a single discard
	blk_queue_max_discard_sectors(mybrd->mybrd_queue, UINT_MAX);

	// don't know why
	mybrd->mybrd_queue->limits.discard_zeroes_data = 1;

	// DISCARD: support discard
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, mybrd->mybrd_queue);


	// complete to init queue
	// there is no mybrd dir in /sys/block yet

	disk = mybrd->mybrd_disk = alloc_disk(1);
	if (!disk)
		goto out_free_queue;

	disk->major = mybrd_major;
	disk->first_minor = 111;
	disk->fops = &mybrd_fops;
	disk->private_data = mybrd;
	disk->queue = mybrd->mybrd_queue;
	disk->flags = GENHD_FL_EXT_DEVT;
	strncpy(disk->disk_name, "mybrd", strlen("mybrd"));
	set_capacity(disk, MYBRD_SIZE_SECT);
	
	pr_warn("end mybrd_alloc\n"); 
	
	return mybrd;

out_free_queue:
	blk_cleanup_queue(mybrd->mybrd_queue);
out_free_brd:
	kfree(mybrd);
out:
	return NULL;
}

static void mybrd_free(struct mybrd_device *mybrd)
{
	blk_cleanup_queue(global_mybrd->mybrd_queue);
	kfree(global_mybrd);
}

static struct kobject *mybrd_probe(dev_t dev, int *part, void *data)
{
	struct kobject *kobj;

	// When probe is called?
	
	pr_warn("start mybrd_probe\n");
	*part = 0; // no partition
	kobj = get_disk(global_mybrd->mybrd_disk);
	pr_warn("end mybrd_probe: ret=%p\n", kobj);
	return kobj;
}

static int __init mybrd_init(void)
{
	mybrd_major = register_blkdev(mybrd_major, "my-ramdisk");
	if (mybrd_major < 0)
		return mybrd_major;

	pr_warn("mybrd major=%d\n", mybrd_major);
	global_mybrd = mybrd_alloc();
	pr_warn("global-mybrd=%p\n", global_mybrd);

	// not yet
	add_disk(global_mybrd->mybrd_disk);

	pr_warn("disk is added..check /sys/block/ and probe?\n");
	
	blk_register_region(MKDEV(mybrd_major, 0), 1UL << MINORBITS,
			    THIS_MODULE,
			    mybrd_probe,
			    NULL, NULL);
	
	pr_warn("\n\n\nmybrd: module loaded\n\n\n\n");
	return 0;
}

static void __exit mybrd_exit(void)
{
	mybrd_free(global_mybrd);

	blk_unregister_region(MKDEV(mybrd_major, 0), 1UL << MINORBITS);
	unregister_blkdev(mybrd_major, "my-ramdisk");
	
	pr_warn("brd: module unloaded\n");
}

module_init(mybrd_init);
module_exit(mybrd_exit);

