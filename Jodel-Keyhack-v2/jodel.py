from collections import OrderedDict
from idautils import *
from idaapi import *
from idc import *
import sys, traceback
import idascript
import decrypt
import re

FUNCTION_PATTERN = 'HmacInterceptor_init'

REGEX_EXTRACT_BYTES = r'(?<=[^ ] )\d\w*'
REGEX_EXTRACT_LOCATION = r'(?<=_)\w*'


def locate_function():
	for segea in Segments():
		for funcea in Functions(segea, SegEnd(segea)):
			functionName = GetFunctionName(funcea)
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
	for i in get_disassembly(locate_function()):
		if 'mov' in i and 'eax' in i:
			raw_value = re.findall(REGEX_EXTRACT_BYTES, i)
			raw_location = re.findall(REGEX_EXTRACT_LOCATION, i)
			value = raw_value[1].replace('h', '').strip()
			if len(value) <= 1 or (8 > len(value) > 3):
				value = '0' + value
			if len(value) > 8 and value.startswith('0'):
				value = value[1:]
			instr[int(raw_location[0], 16)] = rev(value)

	sorted_keys = ''.join(OrderedDict(sorted(instr.items())).values())

	import decrypt
	if len(sorted_keys) != decrypt.CLIENT_SECRET_SIZE*2:
		print("Keysize is {}, should be {} exiting".format(len(sorted_keys), decrypt.CLIENT_SECRET_SIZE*2))
	return [int(sorted_keys[x:x + 2], 16) for x in range(0, len(sorted_keys), 2)]


def rev(a):
	new = ""
	for x in range(-1, -len(a), -2):
		new += a[x-1] + a[x]
	return new


if __name__ == '__main__':
	try:
		key = extract_bytes()
		print('Derived key of length {} from library, now decrypting it...'.format(len(key)))
		print('Got raw key array: {}'.format(key))
		_result = decrypt.decrypt(key)
		print('Got decrypted key: {}'.format(_result))
	except Exception as e:
		print('Exception: {}'.format(e))
		print(traceback.print_exc(file=sys.stdout))
	finally:
		idascript.exit()
