import angr
import os
import sys

rewrite_sites = []
hit_sites = []

def getFuncAddress( funcName, cfg, plt=None ):
	found = [0, 0]

	for addr,func in cfg.kb.functions.iteritems():
		if funcName == func.name and (plt is None or func.is_plt == plt):
			found[0] = addr
			return found		
	raise Exception("No address found for function : "+funcName)

def get_load_addr(insn, found):
	reg = insn >> 5
	reg = reg & 0x0000001F
	print 'reg : x%d' % reg
	if reg == 0:
		return found.se.eval(found.regs.r0)
	elif reg == 1:
		return found.se.eval(found.regs.r1)
	elif reg == 2:
		return found.se.eval(found.regs.r2)
	elif reg == 3:
		return found.se.eval(found.regs.r3)
	elif reg == 4:
		return found.se.eval(found.regs.r4)
	elif reg == 5:
		return found.se.eval(found.regs.r5)
	elif reg == 6:
		return found.se.eval(found.regs.r6)
	elif reg == 7:
		return found.se.eval(found.regs.r7)
	elif reg == 8:
		return found.se.eval(found.regs.r8)
	elif reg == 9:
		return found.se.eval(found.regs.r9)
	elif reg == 10:
		return found.se.eval(found.regs.r10)
	elif reg == 11:
		return found.se.eval(found.regs.r11)
	elif reg == 12:
		return found.se.eval(found.regs.r12)
	elif reg == 13:
		return found.se.eval(found.regs.r13)
	elif reg == 14:
		return found.se.eval(found.regs.r14)
	elif reg == 15:
		return found.se.eval(found.regs.r15)
	elif reg == 16:
		return found.se.eval(found.regs.r16)
	elif reg == 17:
		return found.se.eval(found.regs.r17)
	elif reg == 18:
		return found.se.eval(found.regs.r18)
	elif reg == 19:
		return found.se.eval(found.regs.r19)
	elif reg == 20:
		return found.se.eval(found.regs.r20)
	elif reg == 21:
		return found.se.eval(found.regs.r21)
	elif reg == 22:
		return found.se.eval(found.regs.r22)
	elif reg == 23:
		return found.se.eval(found.regs.r23)
	elif reg == 24:
		return found.se.eval(found.regs.r24)
	elif reg == 25:
		return found.se.eval(found.regs.r25)
	elif reg == 26:
		return found.se.eval(found.regs.r26)
	elif reg == 27:
		return found.se.eval(found.regs.r27)
	elif reg == 28:
		return found.se.eval(found.regs.r28)
	elif reg == 29:
		return found.se.eval(found.regs.r29)
	elif reg == 30:
		return found.se.eval(found.regs.r30)
	return 0

def clear_list(l):
	while len(l) > 0:
		l.pop()

def set_avoids(l, start, end):
	for addr in range(start, end, 4):
		l.append(addr)

def main(binary, function, var):
	project = angr.Project(binary, load_options={'auto_load_libs':False})
	cfg = project.analyses.CFG(fail_fast=True)
	found = getFuncAddress(function, cfg)
	funcAddr = found[0]
	funcSize = project.kb.obj.get_symbol(function).size
	var_addr = project.kb.obj.get_symbol(var).rebased_addr
	var_size = project.kb.obj.get_symbol(var).size

	print 'var_addr : %lx' % var_addr
	print 'var_size : ', var_size
	print 'funcAddr : %lx ~ %lx' % (funcAddr, funcAddr + funcSize)
	print 'funcSize : ', funcSize

	# record all adrp sites
	adrp_sites = []
	avoids = []
	for addr in range(funcAddr, funcAddr + funcSize, 4):
		state = project.factory.entry_state(addr=addr)
		sm = project.factory.simulation_manager(state)
		sm = sm.explore(find=addr)
		if (len(sm.found)) > 0:
			found = sm.found[0]
			insn = found.memory.load(found.ip.args[0], 4, endness='Iend_LE')
			insn = found.se.eval(insn)
			if (insn & 0x9F000000) == 0x90000000:	# If It is adrp,
				adrp_sites.append(found.ip.args[0])
				#break	# testing, first adrp only


	# set each adrp site as entry state, simulate from current adrp site to next adrp site
	# If hit the sensitive data, print 'Hit var!!'
	for idx, adrp_addr in enumerate(adrp_sites):
		if adrp_addr < funcAddr or adrp_addr >= funcAddr + funcSize:
			continue

		startAddr = adrp_addr
		if len(adrp_sites) == idx + 1:	# last one
			endAddr = funcAddr + funcSize
		else:
			endAddr = adrp_sites[idx+1]
		#endAddr = funcAddr + funcSize	# testing

		print ('====== [%lx ~ %lx] =====' % (startAddr, endAddr))
		state = project.factory.entry_state(addr=adrp_addr)
		for addr in range(startAddr, endAddr, 4):
			sm = project.factory.simulation_manager(state)
			sm = sm.explore(find=addr, avoid=avoids)
			if (len(sm.found)) > 0:
				found = sm.found[0]
				insn = found.memory.load(found.ip.args[0], 4, endness='Iend_LE')
				print ('[%lx] %lx' % (found.ip.args[0], found.se.eval(insn)))
				insn = found.se.eval(insn)

				if (insn & 0xff000000) == 0x97000000:	# break when meet bl
					break
				#if (insn & 0xff000000) == 0x14000000:	# meet b to forward
				#	addr = addr + ((insn & 0x000000FF) * 4)
				#	continue
				
				ldr32_reg = insn & 0xFFE00C00
				ldr32_imm = insn & 0xfff00000
				if ldr32_reg == 0xB8600800 or ldr32_imm == 0xB9400000:
					load_addr = get_load_addr(insn, found)
					print ('load_addr : %lx' % load_addr)
					if load_addr >= var_addr and load_addr < var_addr + var_size:
						print 'Hit var!!'
						hit_sites.append([found.ip.args[0], insn])
					else:
						print 'Should be rewritten!!'
						rewrite_sites.append([found.ip.args[0], insn])
	
	print 'total : ', (len(hit_sites) + len(rewrite_sites))
	print 'hit_sites : ', len(hit_sites)
	print 'rewrite_sites : ', len(rewrite_sites)

if __name__ == "__main__":
	if len(sys.argv) != 4:
		print "USAGE: python mem_finder.py <binary path> <function name> <var name>"
		sys.exit(-1)
	
	main(sys.argv[1], sys.argv[2], sys.argv[3])


