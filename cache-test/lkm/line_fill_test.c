#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/thread_info.h>
#include <linux/path.h>
#include <linux/mount.h>
#include <linux/ptrace.h>
#include <linux/pid.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/smp.h>
#include <linux/stop_machine.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/version.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/stringify.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>

//#define CORTEX_A72 1
//#define T32_DEBUG 1

static const unsigned int set_idx = 0;	/* fixed set-idx */
static struct kmem_cache *data_cache = NULL;
static unsigned int *data_array[16] = {NULL,};

/* data dependent on cortex version */
#ifdef CORTEX_A72	/* LRU */
static unsigned int l1_way_size = (16 * 1024);
static unsigned int l1_way_num = 2;
static unsigned int l1_set_num = 256;
static unsigned int l1_line_size = 64;

static unsigned int l2_way_size = 0;	/* configurable. we must fix this value via CCSIDR */
static unsigned int l2_way_num = 16;
static unsigned int l2_set_num = 0;
static unsigned int l2_line_size = 64;
#else /* else == CORTEX_A17, random */
static unsigned int l1_way_size = (8 * 1024);
static unsigned int l1_way_num = 4;
static unsigned int l1_set_num = 128;
static unsigned int l1_line_size = 64;

static unsigned int l2_way_size = 0;	/* configurable. we must fix this value via CCSIDR */
static unsigned int l2_way_num = 16;
static unsigned int l2_set_num = 0;
static unsigned int l2_line_size = 64;
#endif

#include "armv7.h"

typedef struct task_struct* (*kthread_create_fp)(int (*threadfn)(void *data), void *data, unsigned int cpu, const char *namefmt);
kthread_create_fp kthread_create_on_cpu_fp = NULL;

static struct task_struct *threads[2] = {NULL,};

static void fix_l2_set_num(void)
{
	l2_set_num = get_l2_set_num();
	l2_way_size = l2_set_num * l2_line_size;

	pr_info("===== L2 info ========\n");
	pr_info("way size : %d kb\n", l2_way_size / 1024);
	pr_info("set num : %d\n", l2_set_num);
	pr_info("way num : %d\n", l2_way_num);
	pr_info("l2 total size : %d kb\n", (l2_way_size / 1024) * l2_way_num);
	pr_info("======================\n");
}

static void set_kthread_create_fp(void)
{
	kthread_create_on_cpu_fp = (kthread_create_fp)kallsyms_lookup_name("kthread_create_on_cpu");
	if (!kthread_create_on_cpu_fp)
		pr_err("kthread_create_on_cpu_fp is NULL!!\n");
}

static int put_l2_thread(void *data)
{
	unsigned long target_way = (unsigned long)data;
	unsigned int *ptr;
	unsigned int bc, ac, i;

	init_pmu();

	ptr = data_array[0] + (set_idx * l2_line_size / 4);
	*ptr = 0x60708090;
	asm volatile ("isb\n");
	asm volatile ("dmb\n");
	
	flush_dcache(ptr);
	//flush_l1_dcache(set_idx, l1_way_num-1);
	//flush_l2_dcache(set_idx, target_way);
	flush_l1_dcache_all(l1_set_num, l1_way_num);
	flush_l2_dcache_all(l2_set_num, l2_way_num);
	ldr_data(ptr);

#ifdef T32_DEBUG
	asm volatile ("b .");
#endif

	bc = lru_get_cycles();
	ldr_data(ptr);
	ac = lru_get_cycles();
	pr_info("[put_l2_thread-L1_hit] %d\n", ac - bc);

#ifdef T32_DEBUG
	asm volatile ("b .");
#endif

	//flush_l1_dcache(set_idx, l1_way_num-1);
	flush_l1_dcache_all(l1_set_num, l1_way_num);
	bc = lru_get_cycles();
	ldr_data(ptr);
	ac = lru_get_cycles();
	pr_info("[put_l2_thread-L2_hit] %d\n", ac - bc);

	//flush_l1_dcache(set_idx, l1_way_num-1);
	//flush_l2_dcache(set_idx, target_way);
	flush_l1_dcache_all(l1_set_num, l1_way_num);
	flush_l2_dcache_all(l2_set_num, l2_way_num);
	bc = lru_get_cycles();
	ldr_data(ptr);
	ac = lru_get_cycles();
	pr_info("[put_l2_thread-L2_miss] %d\n", ac - bc);
	
	return 0;
}

#if 0
static int read_l2_thread(void *data)
{
	unsigned long target_way = (unsigned long)data;
	unsigned int *ptr;
	unsigned int bc, ac;

	init_pmu();

	ptr = data_array[0] + (set_idx * l2_line_size / 4);
	flush_l1_dcache(set_idx, l1_way_num-1);

	bc = lru_get_cycles();
	ldr_data(ptr);
	ac = lru_get_cycles();
	pr_info("[read_l2_thread-1] %d\n", ac - bc);

	flush_l1_dcache(set_idx, l1_way_num-1);
	flush_l2_dcache(set_idx, target_way);
	
	bc = lru_get_cycles();
	ldr_data(ptr);
	ac = lru_get_cycles();
	pr_info("[read_l2_thread-2] %d\n", ac - bc);

	flush_dcache(ptr);
	return 0;
}
#endif

static void do_line_fill_test(void)
{
	unsigned long target_way;
	unsigned long last_way;
	unsigned i;
	int ret;

	last_way = l2_way_num / 2;
	target_way=l2_way_num - 1;
	for (i=0; i<15; i++) {
		pr_info("====== target way [%ld] =====\n", target_way);
	
		threads[0] = kthread_create_on_cpu_fp(put_l2_thread, (void *)target_way, 0, "put_l2_thread");
		if (IS_ERR(threads[0])) {
			pr_err("kthread_create_on_cpu_fp error\n");
			return;
		}

		ret = kthread_stop(threads[0]);
		if (ret) {
			pr_err("kthread_stop error\n");
			return;
		}
	}
}

void line_fill_test_init(void)
{
	unsigned i;
	
	pr_info("line_fill_test_init\n");

	fix_l2_set_num();
	set_kthread_create_fp();

	/* create data allocator */
	data_cache = kmem_cache_create("line_fill_test_cache", l1_way_size, l2_way_size, SLAB_HWCACHE_ALIGN, NULL);
	if (!data_cache) {
		pr_err("data_cache is NULL\n");
		return;
	}

	/* alloc data_array */
	for (i=0; i<2; i++) {
		data_array[i] = (unsigned int *)kmem_cache_alloc(data_cache, GFP_ATOMIC);
		pr_info("data_array[%d] : %lx\n", i, (unsigned long)data_array[i]);
	}

	do_line_fill_test();
}

void line_fill_test_exit(void)
{
	unsigned i;
	
	pr_info("line_fill_test_exit\n");

	/* free data array */
	for(i=0; i<2; i++)
		kmem_cache_free(data_cache, data_array[i]);

	/* free data allocator */
	kmem_cache_destroy(data_cache);
}

