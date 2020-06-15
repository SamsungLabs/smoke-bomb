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

#define CORTEX_A72 1
//#define T32_DEBUG 1

/* data not dependent on cortex version */
#define PLD_DATA_IDX 16 /* This idx ensures not-set-0 index */
#define LDR_DATA_IDX 17
#define DUMMY_DATA_IDX 18 /* from 2 ~ data_num */

static struct kmem_cache *data_cache = NULL;
static unsigned int *data_array[32] __attribute__((aligned (4096))) = {NULL,};
static unsigned int data_num;
static spinlock_t lru_lock;
static unsigned long lru_flags;

/* data dependent on cortex version */
#ifdef CORTEX_A72
static unsigned int way_size = (16 * 1024);
static unsigned int way_num = 2;
static unsigned int line_size = 64;
static unsigned int set_idx = 0;
static unsigned int set_num = 256;
static unsigned int l1_miss_threshold = 100;
#else /* else == CORTEX_A17 */
static unsigned int way_size = (8 * 1024);
static unsigned int way_num = 4;
static unsigned int line_size = 64;
static unsigned int set_idx = 0;
static unsigned int set_num = 128;
static unsigned int l1_miss_threshold = 100;
#endif

#include "armv7.h"

static void test_cache_hit_miss(void)
{
	unsigned int mc1, mc2, hc1, hc2, i, val = 0;
	unsigned int *ptr;

	ptr = data_array[DUMMY_DATA_IDX];
	*ptr = 0;

	pr_info("===== test_cache_hit_miss =====\n");
	for (i=0; i<3; i++) {
		flush_dcache(ptr);

		mc1 = lru_get_cycles();
		asm volatile ("ldr %0, [%1]\n": "=r" (val): "r" (ptr));
		mc2 = lru_get_cycles();

		hc1 = lru_get_cycles();
		asm volatile ("ldr %0, [%1]\n": "=r" (val): "r" (ptr));
		hc2 = lru_get_cycles();

		pr_info("cache miss : %d\n", mc2 - mc1);
		pr_info("cache hit : %d\n", hc2 - hc1);
		*ptr = val + 2;
	}
	
	pr_info("dummy data : %d\n", *ptr);
	flush_dcache(ptr);
}

static void test_pld(void)
{
	unsigned int mc1, mc2, hc1, hc2, i, val = 0;
	unsigned int *ptr;

	ptr = data_array[DUMMY_DATA_IDX];
	*ptr = 0;

	pr_info("===== test_pld =====\n");
	for (i=0; i<3; i++) {
		flush_dcache(ptr);

		mc1 = lru_get_cycles();
		asm volatile ("ldr %0, [%1]\n": "=r" (val): "r" (ptr));
		mc2 = lru_get_cycles();

		flush_dcache(ptr);
		pld_data(ptr);
		
		hc1 = lru_get_cycles();
		asm volatile ("ldr %0, [%1]\n": "=r" (val): "r" (ptr));
		hc2 = lru_get_cycles();

		pr_info("cache miss : %d\n", mc2 - mc1);
		pr_info("cache hit : %d\n", hc2 - hc1);
		*ptr = val + 2;
	}
	
	pr_info("dummy data : %d\n", *ptr);
	flush_dcache(ptr);
}

static void ldr_test_data(void)
{
	unsigned i;

	/* write first */
	for (i=PLD_DATA_IDX; i<PLD_DATA_IDX + data_num; i++)
		*(data_array[i]) = i;
	
	/* flush */
	for (i=PLD_DATA_IDX; i<PLD_DATA_IDX + data_num; i++)
		flush_dcache(data_array[i]);
	flush_l1_dcache_set(set_idx, set_num);

	ldr_data(data_array[PLD_DATA_IDX]);
	ldr_data(data_array[LDR_DATA_IDX]);

#if 0
	/* preload data */
	for (i=0; i<10; i++)
		pld_data(data_array[PLD_DATA_IDX]);

	/* load data */
	ldr_data(data_array[LDR_DATA_IDX]);
#endif

	/* preload data */
	/*
	for (i=0; i<10; i++)
		pld_data(data_array[PLD_DATA_IDX]);*/

#ifdef T32_DEBUG
	asm volatile ("b .");
#endif
}

static void ldr_dummy_data(int is_pld)
{
	unsigned i;
	
	/* It means triggering cache-replacement!! */
	for (i=DUMMY_DATA_IDX; i<PLD_DATA_IDX + data_num; i++) {
		if(is_pld)
			pld_data(data_array[i]);
		else
			ldr_data(data_array[i]);
	}

#ifdef T32_DEBUG
	asm volatile ("b .");
#endif
}

static void check_result(int is_pld)
{
	unsigned int c1, c2;
	unsigned int *ptr;

	if (is_pld)
		ptr = data_array[PLD_DATA_IDX];
	else
		ptr = data_array[LDR_DATA_IDX];

	c1 = lru_get_cycles();
	ldr_data(ptr);
	c2 = lru_get_cycles();

#ifdef T32_DEBUG
	asm volatile ("b .");
#endif

	pr_info("result-cycle : %d\n", c2 - c1);
}

static int do_lru_test(void *data)
{
	unsigned i;
	
	/* 0. irq disable */
	spin_lock_init(&lru_lock);
	spin_lock_irqsave(&lru_lock, lru_flags);

	/* 1. enable pmu */
	init_pmu();

	/* 2. test */
	test_cache_hit_miss();
	test_pld();

	for (i=0; i<10; i++) {
		/* 3. load test data */
		ldr_test_data();

		/* 4. load dummy data */
		ldr_dummy_data(0);

		/* 5. check what remains in cache, pld-data? or ldr-data */
		if (i >= 5) {
			pr_info("==== check-result-pld [%d] ====\n", i);
			check_result(1);
		}
		else {
			pr_info("==== check-result-ldr [%d] ====\n", i);
			check_result(0);
		}
	}

	/* irq enable */
	spin_unlock_irqrestore(&lru_lock, lru_flags);

	return 0;
}

void lru_test_init(void)
{
	unsigned i;
	unsigned int val = 0;
	unsigned int addr = 0x10203040;

	pr_info("lru_test_init\n");

	/* create data cache allocator */
	data_num = way_num + 2 - 1;
	data_cache = kmem_cache_create("lru_test_cache", sizeof(unsigned int), way_size, 0, NULL);
	if (!data_cache) {
		pr_err("data_cache is NULL\n");
		return;
	}

	/* alloc data_array */
	for (i=PLD_DATA_IDX; i<PLD_DATA_IDX + data_num; i++) {
		data_array[i] = (unsigned int *)kmem_cache_alloc(data_cache, GFP_ATOMIC);
		pr_info("data_array[%d] : %lx\n", i, (unsigned long)data_array[i]);
	}

	/* test!! */
	//stop_machine(do_lru_test, NULL, NULL);
	do_lru_test(NULL);
}

void lru_test_exit(void)
{
	unsigned i;
	pr_info("lru_test_exit\n");

	/* free data array */
	for(i=PLD_DATA_IDX; i<PLD_DATA_IDX + data_num; i++)
		kmem_cache_free(data_cache, data_array[i]);

	/* free data allocator */
	kmem_cache_destroy(data_cache);
}

