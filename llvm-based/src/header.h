#ifndef _SMOKE_BOMB_HEADER_H
#define _SMOKE_BOMB_HEADER_H

#define CACHE_LINE_SIZE 64
#define CACHE_LINE_MASK (~(0x3F))

#ifdef _SMOKE_BOMB_LKM

#include <linux/kernel.h>
#include <linux/pid.h>

#ifdef _SMOKE_BOMB_DEBUG
#define sb_pr_info(...) pr_info(__VA_ARGS__)
#define sb_pr_err(...) pr_err(__VA_ARGS__)
#else /* !_SMOKE_BOMB_DEBUG */
#define sb_pr_info(...)
#define sb_pr_err(...) pr_err(__VA_ARGS__)
#endif

#define SB_MAX_PID 64

typedef unsigned long long phys_addr;
int sb_convert_va_to_pa(unsigned long va, phys_addr *pa);
void sb_preload(void);

struct sensitive_data {
	unsigned int set;
	unsigned long va;
	phys_addr pa;
};

struct sensitive_region {
	unsigned long sva;
	unsigned long eva;
	int preload_flag;
};

extern struct sensitive_data sdata_l1_arr[SB_MAX_PID][2048];
extern struct sensitive_data sdata_l2_arr[SB_MAX_PID][2048];
extern struct sensitive_region sdata_region[SB_MAX_PID];

static inline long get_pid_idx(long pid)
{
	return pid % SB_MAX_PID;
}

#endif /* _SMOKE_BOMB_LKM */


#ifdef _SMOKE_BOMB_ARMV7

#ifdef _SMOKE_BOMB_LKM
#include "arm/cache.h"
#include "arm/insn.h"
#include "arm/patch.h"
#endif

static inline unsigned long get_cycle_count(void)
{
    unsigned long cycles;

    asm volatile ("isb\n");
    asm volatile ("dmb\n");
    asm volatile ("MRC p15, 0, %0, C9, C13, 0\n": "=r" (cycles));
    asm volatile ("isb\n");

    return cycles;
}
#else /* !_SMOKE_BOMB_ARMV7 */

#ifdef _SMOKE_BOMB_LKM
#include "arm64/cache.h"
#include "arm64/insn.h"
#include "arm64/patch.h"
#endif

static inline unsigned long get_cycle_count(void)
{
	unsigned long result = 0;

	asm volatile ("ISB");
	asm volatile ("DMB ISH");
    asm volatile ("MRS %0, PMCCNTR_EL0" : "=r" (result));
    asm volatile ("ISB");
    asm volatile ("DSB SY");
    return result;
}

#endif /* _SMOKE_BOMB_ARMV7 */

struct smoke_bomb_cmd_arg {
	unsigned long sva;		/* start va of protected region */
	unsigned long eva;		/* end va of protected region */
	unsigned long dsva;		/* start va of sensitive data */
	unsigned long deva;		/* end va of sensitive data */
	int sched_policy;
	int sched_prio;
}__attribute__((packed));

struct smoke_bomb_cmd {
	unsigned int cmd;
	struct smoke_bomb_cmd_arg arg;
	int ret;
}__attribute__((packed));

struct smoke_bomb_cmd_vector {
	unsigned int cmd;
	int (*func)(struct smoke_bomb_cmd_arg *);
}__attribute__((packed));

#define SMOKE_BOMB_CMD_INIT 0
#define SMOKE_BOMB_CMD_EXIT 1
#define SMOKE_BOMB_CMD_INIT_PMU 2
#define SMOKE_BOMB_CMD_PRINT_CPUID 3
#define SMOKE_BOMB_CMD_GET_SET_IDX 4
#define SMOKE_BOMB_CMD_PRIME 5
#define SMOKE_BOMB_CMD_PROBE 6

#define SMOKE_BOMB_PROC_NAME "smoke_bomb"
#define SMOKE_BOMB_PROC_FULL_NAME "/proc/smoke_bomb"

#endif
