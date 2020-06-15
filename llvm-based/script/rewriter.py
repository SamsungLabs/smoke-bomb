import os
import sys
import struct
import ctypes
from ctypes import *

sb_insn_dummy1 = 1
sb_insn_dummy2 = 7
sb_insn_op_ldr32_reg = 0
sb_insn_op_ldr32_imm = 1

patch_line_info = []
patch_list = []
hit_list = []

def parse_objdump(binary, optimize):
	fname = binary.split('/')[-1]
	fname += ".patched"
	cmd = "cp -f " + binary + " ./" + fname
	os.system(cmd)

	cmd = "aarch64-linux-gnu-objdump -d " + fname + " > ./dump.txt"
	os.system(cmd)
	hit_ctx = 0
	smoke_bomb_ctx = 0

	f = open("./dump.txt")
	lines = f.readlines()
	for line in lines:
		line = line.strip()

		if line.find(">:") != -1 or line == "":
			continue

		if smoke_bomb_ctx == 1:
			if line.find("smoke_bomb_exit") != -1:
				smoke_bomb_ctx = 0
				continue
		elif smoke_bomb_ctx == 0:
			if line.find("smoke_bomb_init") != -1:
				smoke_bomb_ctx = 1
			else:
				continue
		
		if line.find("smoke_bomb_dummy_init") != -1 and hit_ctx == 0:
			hit_ctx = 1
			continue

		# LDR that should be patched??
		#if patch_ctx == 1:
		token = line.split(' ')
		op = token[1].split('\t')[1]
		if op == "ldr":
			addr = token[0].split(':')[0]
			addr = "0x" + addr
			if long(addr, 0) < long("0x400000", 0):
				offset = long(addr, 0)
			else:
				offset =  long(addr, 0) - long("0x400000", 0)
			insn = token[0].split(':')[1]
			insn = insn.replace('\t', '')
			insn = "0x" + insn
			insn_long = int(insn, 0)

			if token[-1].find("sp") != -1:
				patch_list.append([offset, insn_long])
				patch_line_info.append(line)
				continue

			if hit_ctx == 1:
				if optimize == 1:
					hit_list.append([offset, insn_long])
				else:
					patch_list.append([offset, insn_long])
				hit_ctx = 0
			else:
				patch_list.append([offset, insn_long])
				patch_line_info.append(line)
			
	return fname

def is_ldr32_reg(insn):
	return ((insn & 0xFFF00C00) == 0xB8600800)
	#return ((insn & 0xFFE00C00) == 0xB8600800)

def is_ldr32_imm(insn):
	return ((insn & 0xfff00000) == 0xB9400000)

def convert_ldr32_reg(insn):
	code = 0
	code |= (sb_insn_dummy1 << 26)
	code |= (sb_insn_dummy2 << 21)
	code |= (sb_insn_op_ldr32_reg << 24)

	rm = ((insn & 0x001f0000) >> 16)
	rn = ((insn & 0x000003e0) >> 5)
	rt = ((insn & 0x0000001f))
	option = ((insn & 0x0000e000) >> 13)
	S = ((insn & 0x00001000) >> 12);

	code |= (rm << 16)
	code |= (rn << 5)
	code |= (rt)
	code |= (option << 13)
	code |= (S << 12)
	return code

def convert_ldr32_imm(insn):
	code = 0
	code |= (sb_insn_dummy1 << 26)
	code |= (sb_insn_dummy2 << 21)
	code |= (sb_insn_op_ldr32_imm << 24)

	rn = ((insn & 0x000003e0) >> 5)
	rt = ((insn & 0x0000001f))
	imm = ((insn & 0x001ffc00) >> 10)

	code |= (imm << 10)
	code |= (rn << 5)
	code |= (rt)
	return code

def base256_encode(n, minwidth=0):
	if n > 0:
		arr = []
		while n:
			n, rem = divmod(n, 256)
			arr.append(rem)
		b = bytearray(arr) # little endian
	elif n == 0:
		b = bytearray(b'\x00')
	else:
		raise ValueError

	if minwidth > 0 and len(b) < minwidth:
		b = (minwidth-len(b)) * '\x00' + b
	return b

def patch(fname):
	f = open(fname, "rb")
	buf = bytearray(f.read())
	print len(buf)
	idx = -1

	for off, insn in patch_list:
		idx += 1
		preche = 0
		if is_ldr32_reg(insn):
			preche = convert_ldr32_reg(insn)
		elif is_ldr32_imm(insn):
			preche = convert_ldr32_imm(insn)
		if preche == 0:
			continue
		b = base256_encode(preche)
		#print 'line : ', patch_line_info[idx]
		print ('original : %02x %02x %02x %02x' % (buf[off], buf[off+1], buf[off+2], buf[off+3]))
		print ('patched : %02x %02x %02x %02x' % (b[0], b[1], b[2], b[3]))
		buf[off] = b[0]
		buf[off+1] = b[1]
		buf[off+2] = b[2]
		buf[off+3] = b[3]
	f.close()

	f = open(fname, "wb")
	f.write(buf)
	f.close()

if __name__ == "__main__":
	if len(sys.argv) != 3:
		print "USAGE : python rewriter.py <binary path> <is optimized?>"
		sys.exit(0)

	optimize = int(sys.argv[2])
	fname = parse_objdump(sys.argv[1], optimize)
	patch(fname)
	print 'patches : ', len(patch_list)
	print 'hits : ', len(hit_list)
