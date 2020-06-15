#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/path.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

/*
 * [ cache info ]
 */
unsigned int l1_sets;
unsigned int l1_ways;
unsigned int l2_sets;
unsigned int l2_ways;

#include "../header.h"

#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"

/* data array for prime + probe */
static struct kmem_cache *prime_probe_cache = NULL;
static char *prime_probe_arr[8] = {NULL,};

/* sensitive data array (for now, global!!) */
struct sensitive_data sdata_l1_arr[SB_MAX_PID][2048];
struct sensitive_data sdata_l2_arr[SB_MAX_PID][2048];
struct sensitive_region sdata_region[SB_MAX_PID];

static void smoke_bomb_init_all_sdata_arr(void)
{
	memset(sdata_l1_arr, 0, sizeof(sdata_l1_arr));
	memset(sdata_l2_arr, 0, sizeof(sdata_l2_arr));
	memset(sdata_region, 0, sizeof(sdata_region));
}

static void smoke_bomb_init_sdata_arr(long pid)
{
	sdata_region[pid].sva = 0;
	sdata_region[pid].eva = 0;
	sdata_region[pid].preload_flag = 0;
}

static int smoke_bomb_init_sdata(struct smoke_bomb_cmd_arg *arg)
{
	int r;
	unsigned long sva, eva, va;
	unsigned int set1, set2, way;
	phys_addr pa;
	long pid;

	sva = arg->dsva & CACHE_LINE_MASK;
	eva = arg->deva & CACHE_LINE_MASK;

	pid = get_pid_idx(current->pid);
	if (sdata_region[pid].sva != 0) {
		sb_pr_err("duplicated pid!! %ld\n", pid);
		return -1;
	}
	
	for (va = sva; va < eva; va += CACHE_LINE_SIZE) {
		flush_dcache((void *)va);
		
		/* 0. get pa, and get set number from pa */
		r = sb_convert_va_to_pa(va, &pa);
		if (r) {
			sb_pr_err("sb_convert_va_to_pa error : %lx\n", va);
			return r;
		}

		set1 = get_l1_set_idx_from_addr((void *)pa);
		set2 = get_l2_set_idx_from_addr((void *)pa);

		/* store set info */
		sdata_l1_arr[pid][set1].va = va;
		sdata_l1_arr[pid][set1].pa = pa;
		sdata_l1_arr[pid][set1].set = set1;
		
		sdata_l2_arr[pid][set2].va = va;
		sdata_l2_arr[pid][set2].pa = pa;
		sdata_l2_arr[pid][set2].set = set2;

/* Preload will be performed when first LDRFLUSH is dispatched */
#if 0
		/* 1. Flush L1 */
		for (way=0; way<l1_ways; way++)
			flush_l1_dcache(set1, way);

		/* 2. Flush L2 */
		flush_l2_dcache(set2, l2_ways - 1);

		/* 3. preload */
		pld_data((void *)va);

		/* 4. Flush L2, Keep va in L1 only */
		flush_l2_dcache(set2, l2_ways - 1);
#endif
	}

	sdata_region[pid].sva = sva;
	sdata_region[pid].eva = eva;
	sdata_region[pid].preload_flag = 0;
	
	return 0;
}

static int smoke_bomb_flush(struct smoke_bomb_cmd_arg *arg)
{
	unsigned long sva, eva, va;
	unsigned int set1, set2;
	phys_addr pa;
	int r;
	long pid;

	sva = arg->dsva & CACHE_LINE_MASK;
	eva = arg->deva & CACHE_LINE_MASK;

	pid = get_pid_idx(current->pid);
	for (va = sva; va < eva; va += CACHE_LINE_SIZE) {
		flush_dcache((void *)va);

#if 0
		r = sb_convert_va_to_pa(va, &pa);
		if (r) {
			sb_pr_err("sb_convert_va_to_pa error : %lx\n", va);
			return r;
		}

		set1 = get_l1_set_idx_from_addr((void *)pa);
		set2 = get_l2_set_idx_from_addr((void *)pa);

		flush_l1_dcache(set1, l1_ways - 1);
		flush_l2_dcache(set2, l2_ways - 1);
#endif
	}

	smoke_bomb_init_sdata_arr(pid);
	return 0;
}

/* intialize / finalize test functions */
static int smoke_bomb_cmd_init(struct smoke_bomb_cmd_arg *arg)
{
	int r;

	sb_pr_info("smoke_bomb_cmd_init start\n");

	/* 1. initialize sdata */ 
	r = smoke_bomb_init_sdata(arg);
	if (r) {
		sb_pr_err("smoke_bomb_preload error : %d\n", r);
		return r;
	}

	/* 2. patch for LDRFLUSH */
	/*
	r = patch_user_memory(arg->sva, arg->eva);
	if (r) {
		sb_pr_err("patch_user_memory error : %d\n", r);
		return r;
	}
	*/
	// Already patched by rewriter

	sb_pr_info("smoke_bomb_cmd_init end\n");
	return 0;
}

static int smoke_bomb_cmd_exit(struct smoke_bomb_cmd_arg *arg)
{
	int r;
	
	sb_pr_info("smoke_bomb_cmd_exit start\n");

	/* 1. flush */ 
	r = smoke_bomb_flush(arg);
	if (r) {
		sb_pr_err("smoke_bomb_flush error : %d\n", r);
		return r;
	}
	
	return 0;
}

static int smoke_bomb_cmd_init_pmu(struct smoke_bomb_cmd_arg *arg)
{
	sb_pr_info("smoke_bomb_cmd_init_pmu start\n");
	init_pmu();
	return 0;
}

static int smoke_bomb_print_cpuid(struct smoke_bomb_cmd_arg *arg)
{
	sb_pr_info("cpuid : %d, pid : %d\n", smp_processor_id(), current->pid);
	return 0;
}

static int smoke_bomb_get_set_idx(struct smoke_bomb_cmd_arg *arg)
{
	int r;
	phys_addr pa;
	
	r = sb_convert_va_to_pa(arg->sva, &pa);
	if (r) {
		sb_pr_err("sb_convert_va_to_pa error : %lx\n", arg->sva);
		return r;
	}

	return get_l1_set_idx_from_addr((void *)pa);
}

static int smoke_bomb_prime(struct smoke_bomb_cmd_arg *arg)
{
	int set_idx;
	unsigned int *ptr;
	unsigned i;

	set_idx = smoke_bomb_get_set_idx(arg);
	
	for (i=0; i<l1_ways; i++) {
		ptr = (unsigned int *)(prime_probe_arr[i] + (set_idx * CACHE_LINE_SIZE));
		*ptr = 0;

		flush_dcache(ptr);
		flush_l1_dcache(set_idx, i);
		ldr_data(ptr);
	}

	return 0;
}

static int smoke_bomb_probe(struct smoke_bomb_cmd_arg *arg)
{
	int set_idx;
	unsigned int *ptr;
	unsigned i;
	unsigned int bc = 0, ac = 0, sum = 0;
	int ret;

	select_event_l1d_init();
	set_idx = smoke_bomb_get_set_idx(arg);

	for (i=0; i<l1_ways; i++) {
		ptr = (unsigned int *)(prime_probe_arr[i] + (set_idx * CACHE_LINE_SIZE));

		bc = get_pmu_count();
		ldr_data(ptr);
		ac = get_pmu_count();
		sum += (ac - bc);
	}

	ret = (int)(sum);
	return ret;
}

static struct smoke_bomb_cmd_vector cmds[] = {
	{
		.cmd = SMOKE_BOMB_CMD_INIT,
		.func = smoke_bomb_cmd_init,
	},
	{
		.cmd = SMOKE_BOMB_CMD_EXIT,
		.func = smoke_bomb_cmd_exit,
	},
	{
		.cmd = SMOKE_BOMB_CMD_INIT_PMU,
		.func = smoke_bomb_cmd_init_pmu,
	},
	{
		.cmd = SMOKE_BOMB_CMD_PRINT_CPUID,
		.func = smoke_bomb_print_cpuid,
	},
	{
		.cmd = SMOKE_BOMB_CMD_GET_SET_IDX,
		.func = smoke_bomb_get_set_idx,
	},
	{
		.cmd = SMOKE_BOMB_CMD_PRIME,
		.func = smoke_bomb_prime,
	},
	{
		.cmd = SMOKE_BOMB_CMD_PROBE,
		.func = smoke_bomb_probe,
	},
};

static int smoke_bomb_open(struct inode *inode,struct file *filp)
{
	return 0;
}
static int smoke_bomb_close(struct inode *inode,struct file *filp)
{
	return 0;
}
static ssize_t smoke_bomb_read(struct file *file, char *buf, size_t count, loff_t *off)
{
	return 0;
}

static ssize_t smoke_bomb_write(struct file *file, const char *buf, size_t count, loff_t *data)
{
	struct smoke_bomb_cmd cmd;
	int ret;

	ret = copy_from_user(&cmd, buf, count);
	if (ret) {
		sb_pr_err("copy_from_user error\n");
		return count;
	}

	if (cmd.cmd >= ARRAY_SIZE(cmds)) {
		sb_pr_err("cmd [%d] is not supported\n", cmd.cmd);
		return count;
	}

	/* print cmd info */
	sb_pr_info("cmd : %d\n", cmd.cmd);
	sb_pr_info("sva : %lx\n", cmd.arg.sva);
	sb_pr_info("eva : %lx\n", cmd.arg.eva);
	sb_pr_info("dsva : %lx\n", cmd.arg.dsva);
	sb_pr_info("deva : %lx\n", cmd.arg.deva);

	/* do cmd function */
	((struct smoke_bomb_cmd *)buf)->ret = cmds[cmd.cmd].func(&cmd.arg);
	return count;
}

static struct file_operations smoke_bomb_fops =
{
	.owner = THIS_MODULE,
	.read = smoke_bomb_read,
	.write = smoke_bomb_write,
	.open = smoke_bomb_open,
	.release = smoke_bomb_close,
};

static void smoke_bomb_set_cache_info(void)
{
	l1_sets = get_l1_sets();
	l1_ways = get_l1_ways();
	l2_sets = get_l2_sets();
	l2_ways = get_l2_ways();

	sb_pr_err("L1, sets : %d, ways : %d\n", l1_sets, l1_ways);
	sb_pr_err("L2, sets : %d, ways : %d\n", l2_sets, l2_ways);
}

static void smoke_bomb_init_prime_probe_arr(void)
{
	unsigned i;
	
	prime_probe_cache = kmem_cache_create("prime_probe_cache", l1_sets * CACHE_LINE_SIZE, l1_sets * CACHE_LINE_SIZE, SLAB_HWCACHE_ALIGN, NULL);
	if (prime_probe_cache == NULL) {
		sb_pr_err("kmem_cache_create error\n");
		return;
	}

	for (i=0; i<l1_ways; i++) {
		prime_probe_arr[i] = (char *)kmem_cache_alloc(prime_probe_cache, GFP_ATOMIC);
		sb_pr_info("prime_probe_arr[%d] : %lx\n", i, (unsigned long)(prime_probe_arr[i]));
	}
}

static void smoke_bomb_finalize_prime_probe_arr(void)
{
	unsigned i;
	
	for (i=0; i<l1_ways; i++)
		kmem_cache_free(prime_probe_cache, prime_probe_arr[i]);

	kmem_cache_destroy(prime_probe_cache);
}


#include <asm/opcodes.h>
int __init smoke_bomb_init(void)
{
	int r;
	
	sb_pr_info("smoke_bomb_init\n");
	proc_create(SMOKE_BOMB_PROC_NAME, 0, NULL, &smoke_bomb_fops);
	
	r = fix_unresolve_function_ptrs();
	sb_pr_info("fix_unresolve_function_ptrs : %d\n", r);

	register_ex_handler();
	init_pmu();
	smoke_bomb_set_cache_info();
	smoke_bomb_init_prime_probe_arr();
	smoke_bomb_init_all_sdata_arr();
	return 0;
}

void __exit smoke_bomb_exit(void)
{
	sb_pr_info("smoke_bomb_exit\n");
	remove_proc_entry(SMOKE_BOMB_PROC_NAME, NULL);
	unregister_ex_handler();
	smoke_bomb_finalize_prime_probe_arr();
}

module_init(smoke_bomb_init);
module_exit(smoke_bomb_exit);
MODULE_LICENSE("GPL");

