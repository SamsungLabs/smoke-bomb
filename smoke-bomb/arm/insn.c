#include <linux/kernel.h>
#include <linux/init.h>

#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/traps.h>
#include <asm/opcodes.h>

#include "insn.h"
#include "cache.h"
#include "../header.h"

#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"

#define SB_INSN_DUMMY_1 0x07
#define SB_INSN_DUMMY_2 0x2
#define SB_INSN_DUMMY_3 0x1

/* INSN_OP range :  0x1 ~ 0x3. do not use 0x0 */
#define SB_INSN_OP_LDR_REG 0x1
#define SB_INSN_OP_LDR_IMM 0x2
#define SB_INSN_OP_STR_IMM 0x3

typedef bool (*sb_insn_checker)(insn);
typedef sb_insn (*sb_insn_converter)(insn, insn);
typedef void (*sb_insn_dispatcher)(struct pt_regs *, sb_insn);

struct sb_insn_handler {
	sb_insn op;
	sb_insn_checker checker;
	sb_insn_converter converter;
	sb_insn_dispatcher dispatcher;
};

#define DEFINE_SB_INSN_HANDLER(sb_op, abbr) \
static struct sb_insn_handler handler_##abbr = { \
	.op = sb_op, \
	.checker = is_insn_##abbr, \
	.converter = convert_##abbr, \
	.dispatcher = dispatch_##abbr, \
}

/*
 *******************************************************
 * decoding function for smoke-bomb instruction - start
 *******************************************************
 */
static inline sb_insn sb_get_sb_op(sb_insn code)
{
	return ((code << 8) >> 30);
}
static inline sb_insn sb_get_rm(sb_insn code)
{
	return ((code << 28) >> 28);
}
static inline sb_insn sb_get_rn(sb_insn code)
{
	return ((code << 12) >> 28);
}
static inline sb_insn sb_get_rt(sb_insn code)
{
	return ((code << 16) >> 28);
}
static inline sb_insn sb_get_imm5(sb_insn code)
{
	return ((code << 20) >> 27);
}
static inline sb_insn sb_get_imm12(sb_insn code)
{
	sb_insn sb_code;
	
	sb_code = ((code << 20) >> 27);
	sb_code &= ( ~(SB_INSN_DUMMY_3 << 4) );
	return sb_code;
}
/*
 *******************************************************
 * decoding function for smoke-bomb instruction - end
 *******************************************************
 */


/*
 *****************************************
 * INSN_HANDLER for LDR32-reg - start
 ******************************************
 */
static bool is_insn_ldr_reg(insn code)
{
	return (code & (0xFFF00000)) == (0xE7900000);	/* (code & mask) == val */
}
static sb_insn convert_ldr_reg(insn code, insn sb_op)
{
	sb_insn sb_code = 0;
	insn rn = 0, rt = 0, rm = 0, imm5;

	sb_code |= (SB_INSN_DUMMY_1 << 24);
	sb_code |= (SB_INSN_DUMMY_2 << 20);
	sb_code |= (SB_INSN_DUMMY_3 << 4);
	sb_code |= (sb_op << 22);

	rn = (code << 12) >> 28;
	rt = (code << 16) >> 28;
	rm = (code << 28) >> 28;
	imm5 = (code << 20) >> 27;

	sb_code |= (rn << 16);
	sb_code |= (rt << 12);
	sb_code |= (imm5 << 7);
	sb_code |= (rm);

	return sb_code;
}
static void dispatch_ldr_reg(struct pt_regs *regs, sb_insn sb_code)
{
	sb_insn rn, rt, rm, imm5;
	unsigned int idx, size;
	unsigned int *ptr, *ptr_z;
	unsigned int set1, set2;
	unsigned int bc, ac;
	unsigned long va_z;
	phys_addr pa;
	long pid;

	rn = sb_get_rn(sb_code);
	rt = sb_get_rt(sb_code);
	rm = sb_get_rm(sb_code);
	imm5 = sb_get_imm5(sb_code);
	size = (1 << imm5);

	pid = get_pid_idx(current->pid);

	/*
	 * X (ptr)   :  memory address decoded from LDR
	 * Z (ptr_z) :  pre-loaded data of which set is the same as X
	 */
	
	/* 1. Load/Store X */
	ptr = (unsigned int *)regs->uregs[rn];
	idx = (unsigned int)regs->uregs[rm];
	
	ptr = (unsigned int *)((char *)ptr + (idx * size));

	bc = get_pmu_count();
	regs->uregs[rt] = *ptr; /* perform original LDR instruction */
	ac = get_pmu_count();

	/* 2. Check X */
	if (ac == bc) {
		/* 3. Do nothing */
		;
	}
	else {
		/* 4. Get the set number of X */
		sb_convert_va_to_pa((unsigned long)ptr, &pa);
		set2 = get_l2_set_idx_from_addr((void *)pa);
		va_z = sdata_l2_arr[pid][set2].va;

		/* not related set index!! */
		if (sdata_l2_arr[pid][set2].va == 0)
			return;
		asm volatile ("ISB");
		asm volatile ("DMB ISH");

		/* 5. LDR + Flush L2 */
		set1 = get_l1_set_idx_from_addr((void *)pa);
		
		flush_l1_dcache(set1, l1_ways - 1);
		flush_l2_dcache(set2, l2_ways - 1);
		pld_data((void *)va_z);
		flush_l2_dcache(set2, l2_ways - 1);
	} 
}
/*
 *****************************************
 * INSN_HANDLER for LDR32-reg - end
 ******************************************
 */


/*
 *****************************************
 * INSN_HANDLER for LDR32-imm - start
 ******************************************
 */
static bool is_insn_ldr_imm(insn code)
{
	sb_insn imm12;
	
	if ( (code & (0xFFF00000)) != (0xE5900000) )
		return false;

	imm12 = (code << 20) >> 20;

	/* [ToDo] patch only 1024-align */
	if (imm12 % 1024 != 0)
		return false;
		
	/* patch if bit[4] is 0 */
	if ((imm12 & (SB_INSN_DUMMY_3 << 4)) == (SB_INSN_DUMMY_3 << 4))
		return false;

	return true;
}
static sb_insn convert_ldr_imm(insn code, insn sb_op)
{
	sb_insn sb_code = 0;
	insn rn = 0, rt = 0, imm12 = 0;

	sb_code |= (SB_INSN_DUMMY_1 << 24);
	sb_code |= (SB_INSN_DUMMY_2 << 20);
	sb_code |= (SB_INSN_DUMMY_3 << 4); /* this bit will be ignored at runtime */
	sb_code |= (sb_op << 22);

	rn = (code << 12) >> 28;
	rt = (code << 16) >> 28;
	imm12 = (code << 20) >> 20;

	sb_code |= (rn << 16);
	sb_code |= (rt << 12);
	sb_code |= (imm12);

	return sb_code;
}
static void dispatch_ldr_imm(struct pt_regs *regs, sb_insn sb_code)
{
	sb_insn rn, rt, imm12;
	unsigned int *ptr, *ptr_z;
	unsigned int set1, set2;
	unsigned int bc, ac;
	unsigned long va_z;
	phys_addr pa;
	long pid;

	rn = sb_get_rn(sb_code);
	rt = sb_get_rt(sb_code);
	imm12 = sb_get_imm12(sb_code);

	pid = get_pid_idx(current->pid);

	/*
	 * X (ptr)   :  memory address decoded from LDR
	 * Z (ptr_z) :  pre-loaded data of which set is the same as X
	 */
	
	/* 1. Load/Store X */
	ptr = (unsigned int *)regs->uregs[rn];
	ptr = (unsigned int *)((char *)ptr + imm12);

	bc = get_pmu_count();
	regs->uregs[rt] = *ptr; /* perform original LDR instruction */
	ac = get_pmu_count();

	/* 2. Check X */
	if (ac == bc) {
		/* 3. Do nothing */
		;
	}
	else {
		/* 4. Get the set number of X */
		sb_convert_va_to_pa((unsigned long)ptr, &pa);
		set2 = get_l2_set_idx_from_addr((void *)pa);
		va_z = sdata_l2_arr[pid][set2].va;

		/* not related set index!! */
		if (sdata_l2_arr[pid][set2].va == 0)
			return;
		asm volatile ("ISB");
		asm volatile ("DMB ISH");

		/* 5. LDR + Flush L2 */
		set1 = get_l1_set_idx_from_addr((void *)pa);
		
		flush_l1_dcache(set1, l1_ways - 1);
		flush_l2_dcache(set2, l2_ways - 1);
		pld_data((void *)va_z);
		flush_l2_dcache(set2, l2_ways - 1);
	} 
}
/*
 *****************************************
 * INSN_HANDLER for LDR32-imm - end
 ******************************************
 */

/*
 *****************************************
 * INSN_HANDLER for STR32-imm - start
 ******************************************
 */
static bool is_insn_str_imm(insn code)
{
	sb_insn imm12;
	insn rn = 0, rt = 0;
	
	if ( (code & (0xFFF00000)) != (0xE5800000) )
		return false;

	imm12 = (code << 20) >> 20;
	rn = (code << 12) >> 28;
	rt = (code << 16) >> 28;
		
	/* patch if bit[4] is 0 */
	if ((imm12 & (SB_INSN_DUMMY_3 << 4)) == (SB_INSN_DUMMY_3 << 4))
		return false;

	if (rn >= 10 || rt >= 10)
		return false;

	return true;
}
static sb_insn convert_str_imm(insn code, insn sb_op)
{
	sb_insn sb_code = 0;
	insn rn = 0, rt = 0, imm12 = 0;

	sb_code |= (SB_INSN_DUMMY_1 << 24);
	sb_code |= (SB_INSN_DUMMY_2 << 20);
	sb_code |= (SB_INSN_DUMMY_3 << 4); /* this bit will be ignored at runtime */
	sb_code |= (sb_op << 22);

	rn = (code << 12) >> 28;
	rt = (code << 16) >> 28;
	imm12 = (code << 20) >> 20;

	sb_code |= (rn << 16);
	sb_code |= (rt << 12);
	sb_code |= (imm12);

	return sb_code;
}
static void dispatch_str_imm(struct pt_regs *regs, sb_insn sb_code)
{
	sb_insn rn, rt, imm12;
	unsigned int *ptr, *ptr_z;
	unsigned int set1, set2;
	unsigned int bc, ac;
	unsigned long va_z;
	phys_addr pa;
	long pid;

	rn = sb_get_rn(sb_code);
	rt = sb_get_rt(sb_code);
	imm12 = sb_get_imm12(sb_code);

	pid = get_pid_idx(current->pid);

	/*
	 * X (ptr)   :  memory address decoded from LDR
	 * Z (ptr_z) :  pre-loaded data of which set is the same as X
	 */
	
	/* 1. Load/Store X */
	ptr = (unsigned int *)regs->uregs[rn];
	ptr = (unsigned int *)((char *)ptr + imm12);
	//regs->uregs[rt] = *ptr; /* perform original LDR instruction */

	bc = get_pmu_count();
	*ptr = regs->uregs[rt]; /* perform original STR instruction */
	ac = get_pmu_count();

	/* 2. Check X */
	if (bc == ac) {
		/* 3. Do nothing */
		;
	}
	else {
		/* 4. Get the set number of X */
		sb_convert_va_to_pa((unsigned long)ptr, &pa);
		set2 = get_l2_set_idx_from_addr((void *)pa);
		va_z = sdata_l2_arr[pid][set2].va;

		/* not related set index!! */
		if (sdata_l2_arr[pid][set2].va == 0)
			return;
		asm volatile ("ISB");
		asm volatile ("DMB ISH");

		/* 5. LDR + Flush L2 */
		set1 = get_l1_set_idx_from_addr((void *)pa);
		
		flush_l1_dcache(set1, l1_ways - 1);
		flush_l2_dcache(set2, l2_ways - 1);
		pld_data((void *)va_z);
		flush_l2_dcache(set2, l2_ways - 1);
	} 
}
/*
 *****************************************
 * INSN_HANDLER for STR32-imm - end
 ******************************************
 */



/*
 * [ converter_ldr_reg ]
 * We consier "ldr r3, [r3]" case only.
 * "ldr r3, [fp, #-20]" --> this case is ignored now.
 *
 * additionally, "ldr fp, [sp]" shoule be ignored, too.
 * To ignore the case, skip if Rn or Rt bigger than 0xA (r10)
 *
 * convert "ldr r3, [r3]" to "ldrflush r3, [r3]"
 */
DEFINE_SB_INSN_HANDLER(SB_INSN_OP_LDR_REG, ldr_reg);
DEFINE_SB_INSN_HANDLER(SB_INSN_OP_LDR_IMM, ldr_imm);
//DEFINE_SB_INSN_HANDLER(SB_INSN_OP_STR_IMM, str_imm);

struct sb_insn_handler* handlers[] = {
	NULL,
	&handler_ldr_reg,
	&handler_ldr_imm,
	//&handler_str_imm,
};

/*
 * [ smoke-bomb instruction encoding rule ]
 *
 * ** not fixed.
 *
 * SB_INSN_DUMMY_* makes smoke-bomb instruction to be recognized as undef instruction.
 *
 * [31:24] - SB_INSN_DUMMY_1
 * [23:22] - smoke-bomb opcode (SB_INSN_OP_LDR32_REG, ...)
 * [21:20] - SB_INSN_DUMMY_2
 * [19:16] - Rn
 * [15:12] - Rt
 * [11:7] - imm5
 * [6:5] - type
 * [4] - SB_INSN_DUMMY_3
 * [3:0] - Rm
 *
 * [11:0] can be imm12 for ldr_imm
 */
sb_insn convert_insn_to_sb_insn(insn code)
{
	unsigned i;
	bool r;

	for (i=1; i<ARRAY_SIZE(handlers); i++) {
		r = handlers[i]->checker(code);
		if (r)
			return handlers[i]->converter(code, handlers[i]->op);
	}

	return 0;
}

/* exception handler */
int smoke_bomb_ex_handler(struct pt_regs *regs, unsigned int instr)
{
	sb_insn sb_op;

	sb_op = sb_get_sb_op(instr);
	
	sb_preload();
	handlers[sb_op]->dispatcher(regs, instr);
	
	/* advance pc, and keep going!! */
    regs->ARM_pc += 4;
    return 0;
}


