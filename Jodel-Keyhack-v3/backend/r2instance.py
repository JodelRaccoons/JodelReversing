from collections import OrderedDict

import r2pipe
import re

R2_LIST_FUNCTIONS = 'afl'
R2_DISASSEMBLE_INSTRUCTIONS = 's {}; pi 25'

REGEX_EXTRACT_BYTES = r'(?<=[^ ] )\d\w*'
REGEX_FIND_FUNCTIONS = r'fcn.\w+'


def rev(a):
    new = ""
    for x in range(-1, -len(a), -2):
        new += a[x - 1] + a[x]

    return new


class R2Instance:
    def __init__(self, path):
        self.r2 = r2pipe.open(path)
        self.r2.cmd('aaa')
        self.is_correct_binary = False

        self.key = self.get_method_name()
        if self.key is not False:
            print("Correct binary is {}".format(path))
            self.is_correct_binary = True

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        pass

    def __del__(self):
        self.r2.quit()

    def get_method_name(self):
        func = self.r2.cmd(R2_LIST_FUNCTIONS).split('\r\n')
        regexp = re.compile(REGEX_FIND_FUNCTIONS)
        functions = []
        for f in func:
            reg_res = regexp.search(f)
            if reg_res:
                functions.append(reg_res.group(0))


        possibly_correct1 = []
        for f in functions:
            len = int(self.r2.cmd('s {};pif~?'.format(f)).rstrip())
            if len == 21:
                possibly_correct1.append(f)

        print('PossiblyCorrect1: {}'.format(possibly_correct1))

        count_mov_byte = 8 #should be 8
        count_mov_dword = 8 # should be 8
        count_add_eax = 1 #should be 1
        count_pop_eax = 1 #should be 1

        possibly_correct2 = []
        for f in possibly_correct1:
            instr = self.r2.cmd('s {};pi 18'.format(f))
            _count_move_byte = sum(1 for _ in re.finditer(r'\b%s\b' % re.escape('mov byte'), instr))
            _count_move_dword = sum(1 for _ in re.finditer(r'\b%s\b' % re.escape('mov dword'), instr))
            _count_add_eax = sum(1 for _ in re.finditer(r'\b%s\b' % re.escape('add eax'), instr))
            _count_pop_eax = sum(1 for _ in re.finditer(r'\b%s\b' % re.escape('pop eax'), instr))

            if _count_move_byte == count_mov_byte and _count_move_dword == count_mov_dword and _count_add_eax == count_add_eax and _count_pop_eax == count_pop_eax:
                possibly_correct2.append(f)

        for f in possibly_correct2:
            try:
                return self.extract_bytes(f)
            except Exception as e:
                pass

        return False

    def extract_bytes(self, function_name):
        instr = {}
        # https://memegenerator.net/img/instances/75909642/how-does-this-even-work.jpg
        instructions = [d for d in self.r2.cmd(R2_DISASSEMBLE_INSTRUCTIONS.format(
            function_name)).split('\r') if 'mov' in d and 'eax' in d]
        for i in instructions:
            matches = re.findall(REGEX_EXTRACT_BYTES, i)
            value = matches[1].replace('0x', '').strip()
            if len(value) <= 1 or (8 > len(value) > 2):
                value = '0' + value
            if len(value) > 8 and value.startswith('0'):
                value = value[1:]
            instr[int(matches[0], 0)] = rev(value)

        sorted_keys = ''.join(OrderedDict(sorted(instr.items())).values())

        import decrypt
        if len(sorted_keys) != decrypt.CLIENT_SECRET_SIZE*2:
            print("Keysize is {}, exiting".format(len(sorted_keys)))
        return [int(sorted_keys[x:x + 2], 16) for x in range(0, len(sorted_keys), 2)]
