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

#define SB_INSN_DUMMY_1 0x1 /* [31:26] ==> (SB_INSN_DUMMY_1 << 26) */
#define SB_INSN_DUMMY_2 0x7	/* [23:21] ==> (SB_INSN_DUMMY_2 << 21) */
#define SB_INSN_OP_LDR32_REG 0x0	/* [25:24] ==> (SB_INSN_OP_LDR32_REG << 24) */
#define SB_INSN_OP_LDR32_IMM 0x1
#define SB_INSN_OP_STR32_REG 0x2	/* [25:24] ==> (SB_INSN_OP_STR32_REG << 24) */
#define SB_INSN_OP_STR32_IMM 0x3

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
	return ((code << 6) >> 30);
}
static inline sb_insn sb_get_rm(sb_insn code)
{
	return ((code << 11) >> 27);
}
static inline sb_insn sb_get_rn(sb_insn code)
{
	return ((code << 22) >> 27);
}
static inline sb_insn sb_get_rt(sb_insn code)
{
	return ((code << 27) >> 27);
}
static inline sb_insn sb_get_option(sb_insn code)
{
	return ((code << 16) >> 29);
}
static inline sb_insn sb_get_s(sb_insn code)
{
	return ((code << 19) >> 31);
}
static inline sb_insn sb_get_imm(sb_insn code)
{
	return ((code << 11) >> 21);
}
/*
 *******************************************************
 * decoding function for smoke-bomb instruction - end
 *******************************************************
 */


/*
 *****************************************
 * INSN_HANDLER for LDR32-register - start
 ******************************************
 */
static bool is_insn_ldr32_reg(insn code)
{
	/* (code & mask) == val */
	return ((code & (0xFFE00C00)) == (0xB8600800));
}
static sb_insn convert_ldr32_reg(insn code, insn sb_op)
{
	sb_insn sb_code = 0;
	insn rm = 0, option = 0, S = 0, rn = 0, rt = 0;

	/* 1. set dummy to sb_code */
	sb_code |= (SB_INSN_DUMMY_1 << 26);
	sb_code |= (SB_INSN_DUMMY_2 << 21);
	sb_code |= (sb_op << 24);

	/* 2. get info from code */
	rm = (code << 11) >> 27;
	rn = (code << 22) >> 27;
	rt = (code << 27) >> 27;
	option = (code << 16) >> 29;
	S = (code << 19) >> 31;
	
	/* 3. set info to sb_code */
	sb_code |= (rm << 16);
	sb_code |= (rn << 5);
	sb_code |= (rt);
	sb_code |= (option << 13);
	sb_code |= (S << 12);

	return sb_code;
}
static void dispatch_ldr32_reg(struct pt_regs *regs, sb_insn sb_code)
{
	sb_insn rm, rn, rt;
	unsigned int *ptr, *ptr_z;
	unsigned int idx, set1, set2;
	unsigned int bc, ac;
	unsigned long va_z;
	phys_addr pa;
	long pid;

	rm = sb_get_rm(sb_code);
	rn = sb_get_rn(sb_code);
	rt = sb_get_rt(sb_code);

	pid = get_pid_idx(current->pid);

	/*
	 * X (ptr)   :  memory address decoded from LDR
	 * Z (ptr_z) :  pre-loaded data of which set is the same as X
	 */
	
	/* 1. Load/Store X */
	ptr = (unsigned int *)regs->regs[rn];
	idx = (unsigned int)regs->regs[rm];
	ptr += idx;

	bc = get_pmu_count();
	regs->regs[rt] = *ptr; /* perform original LDR instruction */
	ac = get_pmu_count();

	/* 2. Check X */
	if (ac == bc) {	/* cache-hit case */
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
		/*
			unsigned int i=0, set_sva;
			sb_convert_va_to_pa((unsigned long)sdata_region.sva, &pa);
			set_sva = get_l1_set_idx_from_addr((void *)pa);
			
			if(set_sva == set1){
				va_z = sdata_region.sva;
			}
			else if(set_sva < set1) {
				va_z = sdata_region.sva + (CACHE_LINE_SIZE * (set1 - set_sva));
			}
			else {
				va_z = sdata_region.sva + (CACHE_LINE_SIZE * (64 + (set_sva - set1)));
			}

			for( ; va_z < sdata_region.eva; va_z += CACHE_LINE_SIZE){
				flush_l1_dcache(set1, i++); 
				flush_l2_dcache(set2, l2_ways - 1);
				pld_data((void *)va_z);
			}

			flush_l2_dcache(set2, l2_ways - 1);
		*/
	}
}
/*
 *****************************************
 * INSN_HANDLER for LDR32-register - end
 ******************************************
 */

/*
 *****************************************
 * INSN_HANDLER for LDR32-imm - start
 ******************************************
 */
static bool is_insn_ldr32_imm(insn code)
{
	return ((code & (0xFFF00000)) == (0xB9400000));
	// return ((code & (0xFFE00C00)) == (0xB8400400));
}
static sb_insn convert_ldr32_imm(insn code, insn sb_op)
{
	sb_insn sb_code = 0;
	insn rn = 0, rt = 0, imm = 0;

	/* 1. set dummy to sb_code */
	sb_code |= (SB_INSN_DUMMY_1 << 26);
	sb_code |= (SB_INSN_DUMMY_2 << 21);
	sb_code |= (sb_op << 24);

	/* 2. get info from code */
	rn = (code << 22) >> 27;
	rt = (code << 27) >> 27;
	imm = (code << 11) >> 21;
	
	/* 3. set info to sb_code */
	sb_code |= (imm << 10);
	sb_code |= (rn << 5);
	sb_code |= (rt);

	return sb_code;
}
static void dispatch_ldr32_imm(struct pt_regs *regs, sb_insn sb_code)
{
	sb_insn rn, rt, imm;
	unsigned int *ptr, *ptr_z;
	unsigned int idx, set1, set2;
	unsigned int bc, ac;
	unsigned long va_z;
	phys_addr pa;
	long pid;

	rn = sb_get_rn(sb_code);
	rt = sb_get_rt(sb_code);
	imm = sb_get_imm(sb_code);

	pid = get_pid_idx(current->pid);
	
	/*
	 * X (ptr)   :  memory address decoded from LDR
	 * Z (ptr_z) :  pre-loaded data of which set is the same as X
	 */
	
	/* 1. Load/Store X */
	ptr = (unsigned int *)regs->regs[rn];
	ptr += imm;

	bc = get_pmu_count();
	regs->regs[rt] = *ptr; /* perform original LDR instruction */
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
 * INSN_HANDLER for STR32-register - start
 ******************************************
 */
static bool is_insn_str32_reg(insn code)
{
	/* (code & mask) == val */
	return ((code & (0xFFE00C00)) == (0xB8200800));
}
static sb_insn convert_str32_reg(insn code, insn sb_op)
{
	sb_insn sb_code = 0;
	insn rm = 0, option = 0, S = 0, rn = 0, rt = 0;

	/* 1. set dummy to sb_code */
	sb_code |= (SB_INSN_DUMMY_1 << 26);
	sb_code |= (SB_INSN_DUMMY_2 << 21);
	sb_code |= (sb_op << 24);

	/* 2. get info from code */
	rm = (code << 11) >> 27;
	rn = (code << 22) >> 27;
	rt = (code << 27) >> 27;
	option = (code << 16) >> 29;
	S = (code << 19) >> 31;
	
	/* 3. set info to sb_code */
	sb_code |= (rm << 16);
	sb_code |= (rn << 5);
	sb_code |= (rt);
	sb_code |= (option << 13);
	sb_code |= (S << 12);

	return sb_code;
}
static void dispatch_str32_reg(struct pt_regs *regs, sb_insn sb_code)
{
	sb_insn rm, rn, rt;
	unsigned int *ptr, *ptr_z;
	unsigned int idx, set1, set2;
	unsigned int bc, ac;
	unsigned long va_z;
	phys_addr pa;
	long pid;

	rm = sb_get_rm(sb_code);
	rn = sb_get_rn(sb_code);
	rt = sb_get_rt(sb_code);

	pid = get_pid_idx(current->pid);

	/*
	 * X (ptr)   :  memory address decoded from STR
	 * Z (ptr_z) :  pre-loaded data of which set is the same as X
	 */
	
	/* 1. Load/Store X */
	ptr = (unsigned int *)regs->regs[rn];
	idx = (unsigned int)regs->regs[rm];
	ptr += idx;
	// regs->regs[rt] = *ptr; /* perform original LDR instruction */

	bc = get_pmu_count();
	*ptr = regs->regs[rt]; /* perform original STR instruction */
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
 * INSN_HANDLER for STR32-register - end
 ******************************************
 */

/*
 *****************************************
 * INSN_HANDLER for STR32-imm - start
 ******************************************
 */
static bool is_insn_str32_imm(insn code)
{
	insn rn = 0, rt = 0;
	
	if ((code & (0xFFF00000)) != (0xB9000000))
		return false;

	rn = (code << 22) >> 27;
	rt = (code << 27) >> 27;
	if (rn >= 10 || rt >= 10)
		return false;
	
	return true;
}
static sb_insn convert_str32_imm(insn code, insn sb_op)
{
	sb_insn sb_code = 0;
	insn rn = 0, rt = 0, imm = 0;

	/* 1. set dummy to sb_code */
	sb_code |= (SB_INSN_DUMMY_1 << 26);
	sb_code |= (SB_INSN_DUMMY_2 << 21);
	sb_code |= (sb_op << 24);

	/* 2. get info from code */
	rn = (code << 22) >> 27;
	rt = (code << 27) >> 27;
	imm = (code << 11) >> 21;
	
	/* 3. set info to sb_code */
	sb_code |= (imm << 10);
	sb_code |= (rn << 5);
	sb_code |= (rt);

	return sb_code;
}
static void dispatch_str32_imm(struct pt_regs *regs, sb_insn sb_code)
{
	sb_insn rn, rt, imm;
	unsigned int *ptr, *ptr_z;
	unsigned int idx, set1, set2;
	unsigned int bc, ac;
	unsigned long va_z;
	phys_addr pa;
	long pid;

	rn = sb_get_rn(sb_code);
	rt = sb_get_rt(sb_code);
	imm = sb_get_imm(sb_code);

	pid = get_pid_idx(current->pid);
	
	/*
	 * X (ptr)   :  memory address decoded from STR
	 * Z (ptr_z) :  pre-loaded data of which set is the same as X
	 */
	
	/* 1. Load/Store X */
	ptr = (unsigned int *)regs->regs[rn];
	ptr += imm;
	// regs->regs[rt] = *ptr; /* perform original LDR instruction */

	bc = get_pmu_count();
	*ptr = regs->regs[rt]; /* perform original STR instruction */
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
 * INSN_HANDLER for STR32-imm - end
 ******************************************
 */

/*
 * [ handlers ]
 */
DEFINE_SB_INSN_HANDLER(SB_INSN_OP_LDR32_REG, ldr32_reg);
DEFINE_SB_INSN_HANDLER(SB_INSN_OP_LDR32_IMM, ldr32_imm);
//DEFINE_SB_INSN_HANDLER(SB_INSN_OP_STR32_REG, str32_reg);
//DEFINE_SB_INSN_HANDLER(SB_INSN_OP_STR32_IMM, str32_imm);

struct sb_insn_handler* handlers[] = {
	&handler_ldr32_reg,
	&handler_ldr32_imm,
	//&handler_str32_reg,
	//&handler_str32_imm,
};

/*
 * [ smoke-bomb instruction encoding rule ]
 *
 * ** not fixed.
 *
 * SB_INSN_DUMMY_* makes smoke-bomb instruction to be recognized as undef instruction.
 *
 * [31:26] - SB_INSN_DUMMY_1
 * [25:24] - smoke-bomb opcode (SB_INSN_OP_LDR32_REG, ...)
 * [23:21] - SB_INSN_DUMMY_2
 * [20:16] - Rm
 * [15:13] - option
 * [12] - S
 * [9:5] - Rn
 * [4:0] - Rt
 *
 * [20:10] ==> It can be imm.
 * e.g) ldr Wt, [Rn] ==> read data from Rn, write data to Wt. (W means word, 32bit register)
 */
sb_insn convert_insn_to_sb_insn(insn code)
{
	unsigned i;
	bool r;

	for (i=0; i<ARRAY_SIZE(handlers); i++) {
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
    regs->pc += 4;
    return 0;
}


