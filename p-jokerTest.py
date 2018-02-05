import os
import sys

from capstone import *

CODE = "\x40\xdf\xff\xf0\x00\x10\x0c\x91"
print CODE

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
for (address, size, mnemonic, op_str) in md.disasm_lite(CODE, 0x0):
    print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))


for (address, size, mnemonic, op_str) in md.disasm_lite(CODE, 0xfffffff00746afdc):
    print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))




class aa(object):

    self.bb = list()

if __name__ == '__main__':
    for i in range(10):
        a = aa()

        a.bb.append("ddd")
        print a.bb
