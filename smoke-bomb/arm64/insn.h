#ifndef _SMOKE_BOMB_INSN_H
#define _SMOKE_BOMB_INSN_H

typedef unsigned int insn;		/* original ARM instruction */
typedef unsigned int sb_insn;	/* smoke-bomb defined instruction (kind of undefined instruction) */
struct pt_regs;

sb_insn convert_insn_to_sb_insn(insn code);		/* convert code to sb_insn, return 0 if error */
int smoke_bomb_ex_handler(struct pt_regs *regs, unsigned int instr);

#endif