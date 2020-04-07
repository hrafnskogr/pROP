#! /usr/bin/python3
import distorm3 as distorm
from elftools.elf.elffile import ELFFile
import sys
import signal
import argparse

# Globals
_usage = """\ngadget.py [--b16 | --b32 | --b64] filename\n"""
_args = None

class binary():
	def __init__(self):
		self.bin = None
		self.sections = {}
		self.imagebase = None
		self.selected_section = ""

	def load(self, f):
		try:
			b = open(f, 'rb')
		except Exception as e:
			print("Error reading file: {}".format(e))

		self.bin = b.read()
		elf = ELFFile(b)

		segs = []
		for segment in elf.iter_segments():
			if segment['p_type'] == 'PT_LOAD':
				segs.append(segment['p_paddr'])

		imagebase = segs[0]
		for s in segs:
			if(s < imagebase):
				imagebase = s

		self.imagebase = imagebase

		for sect in elf.iter_sections():
			start = sect['sh_addr']
			size = sect['sh_size']
			end = start + size			

			self.sections[sect.name] = section(sect.name, start, end, size)

	def select_section(self, s):
		self.selected_section = s
		self.sections[self.selected_section].set_file_offsets(self.imagebase)

	def section_fstart(self):
		return self.sections[self.selected_section].fstart_offset

	def section_fend(self):
		return self.sections[self.selected_section].fend_offset

	def pprint(self):
		print("{:24} {:16} {:16} {:16}".format("Name", "Start", "End", "Size"))
		for sect in self.sections:
			s = self.sections[sect]
			print("{:24} {:16} {:16} {:16}".format(s.name, s.str_va_start, s.str_va_end, s.str_size))

		print("imagebase: {}".format(hex(self.imagebase)))

		print("selected section: {}".format(self.selected_section))
		print("section file start offset: {}".format(self.sections[self.selected_section].fstart_offset))
		print("section file end offset: {}".format(self.sections[self.selected_section].fend_offset))
			
class section():
	def __init__(self, name, start, end, size):
		self.name = name
		self.va_start = start
		self.va_end = end
		self.size = size
		self.str_va_start = hex(start)
		self.str_va_end = hex(end)
		self.str_size = hex(size)
		self.fstart_offset = None
		self.fend_offset = None

	def set_file_offsets(self, imagebase):
		self.fstart_offset = self.va_start - imagebase
		self.fend_offset = self.fstart_offset + self.size

def main():
	global _args

	if not args_inquisitor():
		usage()
		sys.exit(1)		

	mybin = binary()
	mybin.load(_args.file)
	mybin.select_section(_args.section)

	all_inst = {}

	for i in range(mybin.section_fstart(), mybin.section_fend()):
		(line, disasm, inst) = extract_gadgets(mybin.imagebase + i, mybin.bin[i:i+20])

		if('ret' not in line):
			continue

		if('db' in line):
			continue

		if(inst in all_inst):
			continue

		all_inst[inst] = True
		
		print("===== Offset: 0x{:x} =====".format(mybin.imagebase+i))
		for d in disasm:
			print("0x{:x}    {}".format(d[0], d[1]))
			if('ret' in d[1]):
				break
		print()

def extract_gadgets(offset, rawcode):
		global _args		

		decoded = distorm.Decode(offset, rawcode, _args.arch)	# returns: (offset, size, instr, hexdump)

		line = ""
		gadget = ""
		disasm = []

		for d in decoded:
			addr = d[0]
			size = d[1]
			asm = d[2].lower()

			inst = "0x{:x}    {}".format(addr, asm)		# instruction: 0x000000    mov eax, ecx
			line += inst + "\n"				# string of all instructions
			gadget += asm + "\n"				# the gadget in itself, as a string
			disasm.append((addr,asm))			# list of each instruction

			if(gadget.find('ret') != -1):
				break
		return (line, disasm, gadget)

		#code = distorm.DecodeGenerator(_file_start_offset, raw, _args.arch)
		#code = distorm.Decode(_file_start_offset, raw, _args.arch)
	
		#for (offset, size, instruction, hexdump) in code:
		#	print("{:08x} {}".format(offset, instruction))

def usage():
	global _usage
	print(_usage)

def signal_handler(sig, frame):
	sys.exit(0)

def args_inquisitor():
	global _usage
	global _args

	parser = argparse.ArgumentParser(description="Gadget Finder", usage = _usage)
	parser.add_argument('file', help="binary file to analyze")
	parser.add_argument('-s', '--section', type=str)
	
	mutex = parser.add_mutually_exclusive_group()
	mutex.add_argument("--b16", action="store_const", dest="arch", const=distorm.Decode16Bits)
	mutex.add_argument("--b32", action="store_const", dest="arch", const=distorm.Decode32Bits)
	mutex.add_argument("--b64", action="store_const", dest="arch", const=distorm.Decode64Bits)

	_args = parser.parse_args()

	if(_args.arch == None) or len(sys.argv)  < 2:
		return False

	return True

if __name__ == "__main__":
	signal.signal(signal.SIGINT, signal_handler)
	main()
