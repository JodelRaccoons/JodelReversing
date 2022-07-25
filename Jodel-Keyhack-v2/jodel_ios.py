from collections import OrderedDict
from idautils import *
from idaapi import *
from idc import *
import sys, traceback
import decrypt
import re

FUNCTION_PATTERN = 'convertNSStringToCString'

REGEX_EXTRACT_LOCATION = r'byte_(\S*)'


def locate_function():
	for segea in Segments():
		found = False
		for funcea in Functions(segea, idc.get_segm_end(segea)):
			functionName = idc.get_func_name(funcea)
			if FUNCTION_PATTERN in functionName:
				found = True
				print("Found function ", functionName, " at ", funcea)
				continue
			if found:
				return funcea
	return None


def get_disassembly(funcea):
	disasm = []
	for (startea, endea) in Chunks(funcea):
			for head in Heads(startea, endea):
				disasm.append(GetDisasm(head))
	return disasm


def extract_key():
	xor_key = "ed25b40c912702e08c2b2a06eae635e03f475cc3"
	target_function = locate_function()
	print("Found function with pattern",FUNCTION_PATTERN, "at",  target_function)

	disasm = get_disassembly(locate_function())
	for asm in disasm:
		if 'MOV' in asm:
			# find offset of key
			raw_location = re.findall(REGEX_EXTRACT_LOCATION, asm)
			# get key bytes
			raw_bytes = idc.get_bytes(int(raw_location[0],16), 40)
			print("Got raw key:", raw_bytes.hex())
			# perform XOR on key with xor_key
			print("Decrypted key:", ''.join([chr(_byte ^ ord(xor_key[count])) for count, _byte in enumerate(raw_bytes)]))
			return


if __name__ == '__main__':
	try:
		key = extract_key()
	except Exception as e:
		print('Exception: {}'.format(e))
		print(traceback.print_exc(file=sys.stdout))
