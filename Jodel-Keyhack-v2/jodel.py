from collections import OrderedDict
from idautils import *
from idaapi import *
from idc import *
import sys, traceback
import decrypt
import re
import ida_hexrays

FUNCTION_PATTERN = 'Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_init'

#REGEX_EXTRACT_BYTES = r'(?<=[^ ] )\d\w*'
REGEX_EXTRACT_BYTES = r'#0x\d\w*'
REGEX_EXTRACT_LOCATION = r'(?<=_)\w*'


def locate_function():
	for segea in Segments():
		for funcea in Functions(segea, idc.get_segm_end(segea)):
			functionName = idc.get_func_name(funcea)
			if FUNCTION_PATTERN in functionName:
				return funcea
	return None


def get_disassembly(funcea):
	disasm = []
	for (startea, endea) in Chunks(funcea):
			for head in Heads(startea, endea):
				disasm.append(GetDisasm(head))
	return disasm


def extract_bytes():
	instr = {}
	target_function = locate_function()
	print("Found function with pattern ",FUNCTION_PATTERN, " at ",  target_function)
	# get decompiled function
	decompiled_function = ida_hexrays.decompile(target_function)
	# get result as string and only match lines containing 0x
	decompiled_instructions = [instr for instr in str(decompiled_function).split("\n") if '0x' in instr]
	# remove prefixes in lines
	decompiled_instructions = [re.sub(r'(byte_|unk_|dword_)', '', instr) for instr in decompiled_instructions]
	# remove whitespaces
	decompiled_instructions = [re.sub(r'(\s)', '', instr) for instr in decompiled_instructions]
	# remove semicolons
	decompiled_instructions = [re.sub(r'(;)', '', instr) for instr in decompiled_instructions]
	# remove 0x prefix
	decompiled_instructions = [re.sub(r'(0x)', '', instr) for instr in decompiled_instructions]

	instructions_dict = dict((int(instr.split("=")[0], 16), rev(str(instr.split("=")[1]))) for instr in decompiled_instructions)

	sorted_keys = ''.join(OrderedDict(sorted(instructions_dict.items())).values())

	print(sorted_keys)

	import decrypt
	if len(sorted_keys) != decrypt.CLIENT_SECRET_SIZE*2:
		print("Keysize is {}, should be {} exiting".format(len(sorted_keys), decrypt.CLIENT_SECRET_SIZE*2))
		return None
	return [int(sorted_keys[x:x + 2], 16) for x in range(0, len(sorted_keys), 2)]


def rev(a):
	new = ""
	for x in range(-1, -len(a), -2):
		new += a[x-1] + a[x]
	return new


if __name__ == '__main__':
	try:
		key = extract_bytes()
		if key:
			print('Derived key of length {} from library, now decrypting it...'.format(len(key)))
			print('Got raw key array: {}'.format(key))
			_result = decrypt.decrypt(key)
			print('Got decrypted key: {}'.format(_result))
	except Exception as e:
		print('Exception: {}'.format(e))
		print(traceback.print_exc(file=sys.stdout))
