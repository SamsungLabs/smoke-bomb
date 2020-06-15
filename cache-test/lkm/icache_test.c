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
#include "armv7.h"

typedef struct task_struct* (*kthread_create_fp)(int (*threadfn)(void *data), void *data, unsigned int cpu, const char *namefmt);

static unsigned int test_data_array[1024] = {10, 20, 30, 40,};
static spinlock_t icache_lock;
static unsigned long icache_flags;

static kthread_create_fp kthread_create_on_cpu_fp = NULL;
static struct task_struct *icache_thread = NULL;

static void set_kthread_create_fp(void)
{
	kthread_create_on_cpu_fp = (kthread_create_fp)kallsyms_lookup_name("kthread_create_on_cpu");
	if (!kthread_create_on_cpu_fp)
		pr_err("kthread_create_on_cpu_fp is NULL!!\n");
}

void __attribute__((aligned (1024 * 16))) test_func(void)
{
	asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n");
	asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n");
	asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n");
	asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n");
	asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n");
	asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n");
	asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n");
	asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n");
	asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n"); asm volatile("nop\n");
}

static void dcache_miss_hit_test(void)
{
	unsigned int *ptr = test_data_array;
	unsigned int bc, ac;
	
	flush_dcache(ptr);

	bc = lru_get_cycles();
	ldr_data(ptr);
	ac = lru_get_cycles();
	pr_info("dcache-1 : %d cycles\n", ac - bc);

	bc = lru_get_cycles();
	ldr_data(ptr);
	ac = lru_get_cycles();
	pr_info("dcache-2 : %d cycles\n", ac - bc);
}

static const unsigned int test_repeat = 1000;
static int icache_miss_hit_test_core_1(void *data)
{
	unsigned int *ptr = (unsigned int *)test_func;
	unsigned int bc, ac;
	init_pmu();

	flush_icache(ptr);
	flush_dcache(ptr);

	bc = lru_get_cycles();
	ldr_data(ptr);
	ac = lru_get_cycles();
	pr_info("instruction, icache-1 : %d cycles\n", ac - bc);

	flush_icache(ptr);
	flush_dcache(ptr);

	bc = lru_get_cycles();
	test_func();
	test_func();
	ac = lru_get_cycles();
	pr_info("instruction, running time-1 : %d cycles\n", ac - bc);

	/* flush ptr-instr in L1 icache, and keep it in L2 only */
	flush_icache(ptr);
	return 0;
}

static int icache_miss_hit_test_core_2(void *data)
{
	unsigned int *ptr = (unsigned int *)test_func;
	unsigned int bc, ac;
	init_pmu();

	bc = lru_get_cycles();
	ldr_data(ptr);
	ac = lru_get_cycles();
	pr_info("instruction, icache-2 : %d cycles\n", ac - bc);

	bc = lru_get_cycles();
	test_func();
	test_func();
	ac = lru_get_cycles();
	pr_info("instruction, running time-2 : %d cycles\n", ac - bc);

	flush_icache(ptr);
	flush_dcache(ptr);
	
	return 0;
}

void do_icache_test(void)
{
	int ret;

	icache_thread = kthread_create_on_cpu_fp(icache_miss_hit_test_core_1, NULL, 1, "icache_thread");
	if (IS_ERR(icache_thread)) {
		pr_err("kthread_create_on_cpu_fp error\n");
		return;
	}

	ret = kthread_stop(icache_thread);
	if (ret) {
		pr_err("kthread_stop error\n");
		return;
	}

	icache_thread = kthread_create_on_cpu_fp(icache_miss_hit_test_core_2, NULL, 2, "icache_thread");
	if (IS_ERR(icache_thread)) {
		pr_err("kthread_create_on_cpu_fp error\n");
		return;
	}

	ret = kthread_stop(icache_thread);
	if (ret) {
		pr_err("kthread_stop error\n");
		return;
	}
}

void icache_test_init(void)
{
	pr_info("icache_test_init\n");

	set_kthread_create_fp();
	do_icache_test();
}

void icache_test_exit(void)
{
	pr_info("icache_test_exit\n");
}

