
import os
import sys
sys.path.append("../")
from kernel.offset import MachOHeader
from kernel.kernel import KernelMachO
from capstone import *
from print_xformat import to_hex, to_x
from arm_regs import *
from OSMetaClass import OSMetaClass

from print_color import *
from TypeParser import *

OSMetaClass_OSMetaClass_VMaddr = 0
IOUserClient_VMaddr = 0
IOService_VMaddr = 0

STRING_TAB = {}

BASE_CLASS = {}
DRIVER_CLASS = {}
META_CLASSES = {}


prelink_kext_vm = -1
prelink_kext_f = -1
prelink_kext_size = -1


def init_kernel_header(kernel_f):
    macho_file = open(kernel_f, "rb")
    macho_file.seek(0, 2)
    size = macho_file.tell()
    macho_file.seek(0)
    return MachOHeader(macho_file, 0, size)

def init_kext_header(kernel_f, kext_f):
    macho_file = open(kernel_f, "rb")
    macho_file.seek(0, 2)
    size = macho_file.tell()
    return MachOHeader(macho_file, kext_f, size)


def get_single_IMM(insn):
    seg_num = insn.op_count(CS_OP_IMM)
    if seg_num > 1:
        print "Extract: too much imm reg!"
    if seg_num != 1:
        print "Extract: no imm reg found!"
    return to_x(insn.op_find(CS_OP_IMM, 1).value.imm)

def get_mem_op_offset(insn):
    mem_num = insn.op_count(CS_OP_MEM)
    if mem_num >= 1:
        offset = insn.op_find(CS_OP_MEM, 1).mem.disp
        return offset

def get_mem_op_reg(insn):
    mem_num = insn.op_count(CS_OP_MEM)
    if mem_num >= 1:
        offset = insn.op_find(CS_OP_MEM, 1).mem.base
        return offset

def get_first_reg(insn):
    return insn.op_find(CS_OP_REG, 1).value.reg


def get_second_reg(insn):
    return insn.op_find(CS_OP_REG, 2).value.reg

def prepare_string(k_header):
    global STRING_TAB

    string_table_f = k_header.macho_get_fileaddr("__STRINGTAB", "")
    string_table_size = k_header.macho_get_size("__STRINGTAB", "")
    symbol_table_f = k_header.macho_get_fileaddr("__SYMTAB", "")
    sym_num = k_header.macho_get_size("__SYMTAB", "")

    strings = k_header.memcpy(string_table_f, string_table_size)
    strings_list = strings.split("\x00")

    offset = symbol_table_f
    for i in range(sym_num):
        index = k_header.memcpy(offset, 4)
        addr = k_header.memcpy(offset + 8, 8)
        string = k_header.get_memStr_from_f(string_table_f + index)
        STRING_TAB[addr] = string
        offset += 16


def prepare_offset(k_header):
    global prelink_kext_vm
    global prelink_kext_f
    global prelink_kext_size

    global prelink_data_vm
    global prelink_data_f

    prelink_kext_vm   = k_header.macho_get_vmaddr("__PRELINK_TEXT", "")
    prelink_kext_f    = k_header.macho_get_fileaddr("__PRELINK_TEXT", "")
    prelink_kext_size = k_header.macho_get_size("__PRELINK_TEXT", "")

    prelink_data_vm   = k_header.macho_get_vmaddr("__PRELINK_DATA", "")
    prelink_data_f    = k_header.macho_get_fileaddr("__PRELINK_DATA", "")
    print hex(prelink_data_f), hex(prelink_data_vm)

def setup_OSMetaClassFunc(k_header):
    global OSMetaClass_OSMetaClass_VMaddr
    base_vmaddr = k_header.macho_get_vmaddr("__TEXT", None)
    mod_init_vmaddr = k_header.macho_get_vmaddr("__DATA_CONST", "__mod_init_func")
    mod_init_fileaddr = k_header.macho_get_fileaddr("__DATA_CONST", "__mod_init_func")
    mod_init_size = k_header.macho_get_size("__DATA_CONST", "__mod_init_func")

    text_exec_fileaddr = k_header.macho_get_fileaddr("__TEXT_EXEC", "__text")
    text_exec_size = k_header.macho_get_size("__TEXT_EXEC", "__text")
    osmetaclass_vm = 0

    func_init_1 = k_header.memcpy(mod_init_fileaddr + 0x8, 8)
    if func_init_1 < mod_init_vmaddr:
        print "Extract: wrong func init addr"
        exit(1)

    cs_handler = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    cs_handler.detail = True     # this is very important
    code = k_header.memcpy(func_init_1 - base_vmaddr, 0xfff)
    cs_insn = cs_handler.disasm(code, func_init_1)
    for insn in cs_insn:
        address = insn.address
        mnemonic = insn.mnemonic
        op_str = insn.op_str
        #print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))
        if not cmp(mnemonic, "bl"):
            bl_addr = get_single_IMM(insn)
            if bl_addr and osmetaclass_vm:
                print "Extract: too many bl instr in the Mod_Func_Init_1"
            if bl_addr:
                osmetaclass_vm = bl_addr
        if not cmp(mnemonic, "ret"):
            break
    OSMetaClass_OSMetaClass_VMaddr = osmetaclass_vm


def get_all_metaclass(k_header=None, iskext=False):  # mod init func
    global IOUserClient_VMaddr
    global IOService_VMaddr
    global META_CLASSES

    mod_init_vmaddr = k_header.macho_get_vmaddr("__DATA_CONST", "__mod_init_func")
    mod_init_fileaddr = k_header.macho_get_fileaddr("__DATA_CONST", "__mod_init_func")
    mod_init_size = k_header.macho_get_size("__DATA_CONST", "__mod_init_func")

    total_mif = mod_init_size / 8
    print "Extract: total %d kernel base object modinit" % total_mif

    for i in range(0, total_mif):
        each_mif_vm = k_header.get_mem_from_vmaddr(mod_init_fileaddr, mod_init_vmaddr, mod_init_vmaddr + i * 8)
        each_mif_f = k_header.get_f_from_vm(mod_init_fileaddr, mod_init_vmaddr, each_mif_vm)

        cs_handler = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        cs_handler.detail = True  # this is very important
        code = k_header.memcpy(each_mif_f, 0xfff)
        cs_insn = cs_handler.disasm(code, each_mif_vm)

        for insn in cs_insn:
            address = insn.address
            mnemonic = insn.mnemonic
            op_str = insn.op_str
            # print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))

            if not (cmp(mnemonic, "adrp") and cmp(mnemonic, "adr")):
                imm = get_single_IMM(insn)
                seg_num = insn.op_count(CS_OP_REG)
                if seg_num > 2:
                    print "Extract: too many regs!"
                index = insn.op_find(CS_OP_REG, 1)
                s_reg = index.value.reg
                set_actual_value_by_regN(s_reg, eval(imm))

            if not cmp(mnemonic, "add"):
                seg_num = insn.op_count(CS_OP_REG)
                if seg_num == 2:
                    imm_num = insn.op_count(CS_OP_IMM)
                    if imm_num == 1:
                        imm = get_single_IMM(insn)
                        f_reg = get_first_reg(insn)
                        s_reg = get_second_reg(insn)
                        if s_reg == arm64_const.ARM64_REG_SP:
                            continue
                        s_reg_v = get_actual_value_by_regN(s_reg)
                        f_reg_v = s_reg_v + eval(imm)
                        set_actual_value_by_regN(f_reg, f_reg_v)
                    elif imm_num > 2:
                        print "Extract: add op has two or more imm!"
                        exit(1)

            if not (cmp(mnemonic, "mov") and cmp(mnemonic, "movz")) :
                reg_num = insn.op_count(CS_OP_REG)
                if reg_num == 2:
                    # mov between two regs
                    s_reg = get_second_reg(insn)
                    if s_reg == arm64_const.ARM64_REG_SP:
                        continue
                    s_reg_v = get_actual_value_by_regN(s_reg)
                    if not s_reg_v:
                        continue
                    f_reg = get_first_reg(insn)
                    set_actual_value_by_regN(f_reg, s_reg_v)
                    #print hex(get_actual_value_by_regN(f_reg))
                else:
                    # mov only have one imm
                    imm = get_single_IMM(insn)
                    f_reg = get_first_reg(insn)
                    set_actual_value_by_regN(f_reg, eval(imm))

            if not cmp(mnemonic, "orr"):
                reg_num = insn.op_count(CS_OP_REG)
                if reg_num == 2:
                    s_reg = get_second_reg(insn)
                    if s_reg == arm64_const.ARM64_REG_WZR:
                        if insn.op_count(CS_OP_IMM) == 1:
                            imm = get_single_IMM(insn)
                            f_reg = get_first_reg(insn)
                            set_actual_value_by_regN(f_reg, eval(imm))
                        else:
                            exit(1)

            if not cmp(mnemonic, "ldr"):
                reg_num = insn.op_count(CS_OP_REG)
                if reg_num == 1:
                    f_reg = get_first_reg(insn)
                    imem_num = insn.op_count(CS_OP_MEM)
                    if imem_num:
                        mem_offset = get_mem_op_offset(insn)
                        s_reg = get_mem_op_reg(insn)
                        s_reg_v = get_actual_value_by_regN(s_reg)
                        #set_actual_value_by_regN(s_reg, s_reg_v + mem_offset)
                        #print s_reg, get_actual_value_by_regN(s_reg)
                        if s_reg_v is None:
                            continue
                        #print hex(each_mif_f), hex(each_mif_vm), hex(s_reg_v + mem_offset)
                        #print hex(k_header.get_prelinkf_from_vm(s_reg_v + mem_offset))
                        #print hex(k_header.prelink_offset)
                        if iskext:
                            # fuck!!!, the file offset
                            if (s_reg_v + mem_offset) >= prelink_data_vm:
                                x_reg_mem_v = k_header.kernel_header.memcpy(
                                    k_header.get_f_from_vm(prelink_data_f, prelink_data_vm, s_reg_v + mem_offset), 8)
                            else:
                                try:
                                    x_reg_mem_v = k_header.kernel_header.memcpy(k_header.get_prelinkf_from_vm(
                                        s_reg_v + mem_offset), 8)
                                except:
                                    break
                        else:
                            x_reg_mem_v = k_header.get_mem_from_vmaddr(each_mif_f, each_mif_vm,
                                                                       s_reg_v + mem_offset)
                        set_actual_value_by_regN(f_reg, x_reg_mem_v)

            if not cmp(mnemonic, "bl"):
                if insn.op_count(CS_OP_IMM):
                    bl_addr_vm = get_single_IMM(insn)
                    meta_class = OSMetaClass()
                    if bl_addr_vm == OSMetaClass_OSMetaClass_VMaddr:
                        #meta_class = OSMetaClass()

                        meta_class.class_self_addr  = get_actual_value_by_regN(arm64_const.ARM64_REG_X0)
                        meta_class.class_name_addr  = get_actual_value_by_regN(arm64_const.ARM64_REG_X1)
                        meta_class.class_super_addr = get_actual_value_by_regN(arm64_const.ARM64_REG_X2)
                        meta_class.class_size       = get_actual_value_by_regN(arm64_const.ARM64_REG_X3)

                        if meta_class.class_name_addr:
                            meta_class.class_name = k_header.get_memStr_from_vmaddr(each_mif_f, each_mif_vm, meta_class.class_name_addr)
                            if not cmp(meta_class.class_name, "IOUserClient"):
                                IOUserClient_VMaddr = meta_class.class_self_addr
                            if not cmp(meta_class.class_name, "IOService"):
                                IOService_VMaddr = meta_class.class_self_addr
                        else:
                            meta_class.class_name = "unknow classname"
                        META_CLASSES[meta_class.class_self_addr] = meta_class
                        continue

                    bl_addr_vm = int(bl_addr_vm, 16)
                    bl_addr_f = k_header.get_f_from_vm(each_mif_f, each_mif_vm, bl_addr_vm)
                    bl_indrect_addr = get_jump_addr(k_header, cs_handler, bl_addr_vm, bl_addr_f)

                    if hex(bl_indrect_addr).strip("L") == OSMetaClass_OSMetaClass_VMaddr:

                        meta_class.class_self_addr = get_actual_value_by_regN(arm64_const.ARM64_REG_X0)
                        meta_class.class_name_addr = get_actual_value_by_regN(arm64_const.ARM64_REG_X1)
                        meta_class.class_super_addr = get_actual_value_by_regN(arm64_const.ARM64_REG_X2)
                        meta_class.class_size = get_actual_value_by_regN(arm64_const.ARM64_REG_X3)

                        if meta_class.class_name_addr:
                            meta_class.class_name = k_header.get_memStr_from_vmaddr(each_mif_f, each_mif_vm,
                                                                                         meta_class.class_name_addr)
                            if not cmp(meta_class.class_name, "IOUserClient"):
                                IOUserClient_VMaddr = meta_class.class_self_addr
                            if not cmp(meta_class.class_name, "IOService"):
                                IOService_VMaddr = meta_class.class_self_addr
                        else:
                            meta_class.class_name = "unknow classname"
                        META_CLASSES[meta_class.class_self_addr] = meta_class

            if not cmp(mnemonic, "ret"):
                break

            if not cmp(mnemonic, "b"):
                break


def analysis_mif(k_header=None, iskext=False):  # mod init func
    global IOUserClient_VMaddr
    global IOService_VMaddr

    global prelink_data_vm
    global prelink_data_f

    mod_init_vmaddr = k_header.macho_get_vmaddr("__DATA_CONST", "__mod_init_func")
    mod_init_fileaddr = k_header.macho_get_fileaddr("__DATA_CONST", "__mod_init_func")
    mod_init_size = k_header.macho_get_size("__DATA_CONST", "__mod_init_func")

    total_mif = mod_init_size / 8
    print "Extract: total %d kernel base object modinit" % total_mif

    for i in range(1, total_mif):
        each_mif_vm = k_header.get_mem_from_vmaddr(mod_init_fileaddr, mod_init_vmaddr, mod_init_vmaddr + i * 8)
        each_mif_f = k_header.get_f_from_vm(mod_init_fileaddr, mod_init_vmaddr, each_mif_vm)

        cs_handler = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        cs_handler.detail = True  # this is very important
        code = k_header.memcpy(each_mif_f, 0xfff)
        cs_insn = cs_handler.disasm(code, each_mif_vm)

        for insn in cs_insn:
            address = insn.address
            mnemonic = insn.mnemonic
            op_str = insn.op_str

            #if iskext:
            #print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))

            if not (cmp(mnemonic, "adrp") and cmp(mnemonic, "adr")):
                imm = get_single_IMM(insn)
                seg_num = insn.op_count(CS_OP_REG)
                if seg_num > 2:
                    print "Extract: too many regs!"
                index = insn.op_find(CS_OP_REG, 1)
                s_reg = index.value.reg
                set_actual_value_by_regN(s_reg, eval(imm))

            if not cmp(mnemonic, "add"):
                seg_num = insn.op_count(CS_OP_REG)
                if seg_num == 2:
                    imm_num = insn.op_count(CS_OP_IMM)
                    if imm_num == 1:
                        imm = get_single_IMM(insn)
                        f_reg = get_first_reg(insn)
                        s_reg = get_second_reg(insn)
                        if s_reg == arm64_const.ARM64_REG_SP:
                            continue
                        s_reg_v = get_actual_value_by_regN(s_reg)
                        f_reg_v = s_reg_v + eval(imm)
                        set_actual_value_by_regN(f_reg, f_reg_v)
                    elif imm_num > 2:
                        print "Extract: add op has two or more imm!"
                        exit(1)

            if not (cmp(mnemonic, "mov") and cmp(mnemonic, "movz")) :
                reg_num = insn.op_count(CS_OP_REG)
                if reg_num == 2:
                    # mov between two regs
                    s_reg = get_second_reg(insn)
                    if s_reg == arm64_const.ARM64_REG_SP:
                        continue
                    s_reg_v = get_actual_value_by_regN(s_reg)
                    if not s_reg_v:
                        continue
                    f_reg = get_first_reg(insn)
                    set_actual_value_by_regN(f_reg, s_reg_v)
                    #print hex(get_actual_value_by_regN(f_reg))
                else:
                    # mov only have one imm
                    imm = get_single_IMM(insn)
                    f_reg = get_first_reg(insn)
                    set_actual_value_by_regN(f_reg, eval(imm))

            if not cmp(mnemonic, "orr"):
                reg_num = insn.op_count(CS_OP_REG)
                if reg_num == 2:
                    s_reg = get_second_reg(insn)
                    if s_reg == arm64_const.ARM64_REG_WZR:
                        if insn.op_count(CS_OP_IMM) == 1:
                            imm = get_single_IMM(insn)
                            f_reg = get_first_reg(insn)
                            set_actual_value_by_regN(f_reg, eval(imm))
                        else:
                            exit(1)

            if not cmp(mnemonic, "ldr"):
                reg_num = insn.op_count(CS_OP_REG)
                if reg_num == 1:
                    f_reg = get_first_reg(insn)
                    imem_num = insn.op_count(CS_OP_MEM)
                    if imem_num:
                        mem_offset = get_mem_op_offset(insn)
                        s_reg = get_mem_op_reg(insn)
                        s_reg_v = get_actual_value_by_regN(s_reg)
                        # set_actual_value_by_regN(s_reg, s_reg_v + mem_offset)
                        # print s_reg, get_actual_value_by_regN(s_reg)
                        if s_reg_v is None:
                            continue
                        # print hex(each_mif_f), hex(each_mif_vm), hex(s_reg_v + mem_offset)
                        # print hex(k_header.get_prelinkf_from_vm(s_reg_v + mem_offset))
                        if iskext:
                            if (s_reg_v + mem_offset) >= prelink_data_vm:
                                x_reg_mem_v = k_header.kernel_header.memcpy(
                                    k_header.get_f_from_vm(prelink_data_f, prelink_data_vm, s_reg_v + mem_offset), 8)
                            else:
                                x_reg_mem_v = k_header.kernel_header.memcpy(k_header.get_prelinkf_from_vm(
                                    s_reg_v + mem_offset), 8)
                        else:
                            x_reg_mem_v = k_header.get_mem_from_vmaddr(each_mif_f, each_mif_vm,
                                                                       s_reg_v + mem_offset)
                        set_actual_value_by_regN(f_reg, x_reg_mem_v)

            if not cmp(mnemonic, "bl"):
                if insn.op_count(CS_OP_IMM):
                    bl_addr_vm = get_single_IMM(insn)
                    meta_class = OSMetaClass()
                    if bl_addr_vm == OSMetaClass_OSMetaClass_VMaddr:
                        #meta_class = OSMetaClass()

                        meta_class.class_self_addr  = get_actual_value_by_regN(arm64_const.ARM64_REG_X0)
                        meta_class.class_name_addr  = get_actual_value_by_regN(arm64_const.ARM64_REG_X1)
                        meta_class.class_super_addr = get_actual_value_by_regN(arm64_const.ARM64_REG_X2)
                        meta_class.class_size       = get_actual_value_by_regN(arm64_const.ARM64_REG_X3)

                        if meta_class.class_name_addr:
                            meta_class.class_name = k_header.get_memStr_from_vmaddr(each_mif_f, each_mif_vm, meta_class.class_name_addr)
                            if not cmp(meta_class.class_name, "IOUserClient"):
                                IOUserClient_VMaddr = meta_class.class_self_addr
                            if not cmp(meta_class.class_name, "IOService"):
                                IOService_VMaddr = meta_class.class_self_addr
                        else:
                            meta_class.class_name = "unknow classname"
                        each_meta_class = meta_class

                    bl_addr_vm = int(bl_addr_vm, 16)
                    bl_addr_f = k_header.get_f_from_vm(each_mif_f, each_mif_vm, bl_addr_vm)
                    # print hex(bl_addr_f), hex(bl_addr_vm)
                    bl_indrect_addr = get_jump_addr(k_header, cs_handler, bl_addr_vm, bl_addr_f)

                    if hex(bl_indrect_addr).strip("L") == OSMetaClass_OSMetaClass_VMaddr:

                        meta_class.class_self_addr = get_actual_value_by_regN(arm64_const.ARM64_REG_X0)
                        meta_class.class_name_addr = get_actual_value_by_regN(arm64_const.ARM64_REG_X1)
                        meta_class.class_super_addr = get_actual_value_by_regN(arm64_const.ARM64_REG_X2)
                        meta_class.class_size = get_actual_value_by_regN(arm64_const.ARM64_REG_X3)

                        if meta_class.class_name_addr:
                            meta_class.class_name = k_header.get_memStr_from_vmaddr(each_mif_f, each_mif_vm,
                                                                                         meta_class.class_name_addr)
                            if not cmp(meta_class.class_name, "IOUserClient"):
                                IOUserClient_VMaddr = meta_class.class_self_addr
                            if not cmp(meta_class.class_name, "IOService"):
                                IOService_VMaddr = meta_class.class_self_addr
                        else:
                            meta_class.class_name = "unknow classname"

            if not cmp(mnemonic, "str"):
                reg_num = insn.op_count(CS_OP_REG)
                # something wrong here when run on macOS, maybe the capstone version is update
                if reg_num == 1:
                    continue

                f_reg = get_first_reg(insn)
                #print f_reg
                if f_reg == arm64_const.ARM64_REG_XZR or f_reg == arm64_const.ARM64_REG_D0 or\
                                f_reg == arm64_const.ARM64_REG_WZR:
                    continue
                
                s_reg = get_second_reg(insn)

                if s_reg:
                    s_reg_v = get_actual_value_by_regN(s_reg)
                    if not (s_reg_v and s_reg_v == meta_class.class_self_addr):
                        continue
                else:
                    continue

                f_reg_v_vm = get_actual_value_by_regN(f_reg)
                if iskext:
                    f_reg_v_f = k_header.get_prelinkf_from_vm(f_reg_v_vm)
                else:
                    f_reg_v_f = k_header.get_f_from_vm(each_mif_f, each_mif_vm, f_reg_v_vm)

                parse_const_func(k_header, meta_class, f_reg_v_vm,
                                 f_reg_v_f, iskext)

            if not cmp(mnemonic, "ret"):
                break

            if not cmp(mnemonic, "b"):
                break


def parse_const_func(k_header, meta_class, x_metaclass_vt_vm, x_metaclass_vt_f, iskext=False):
    global STRING_TAB
    global BASE_CLASS
    global DRIVER_CLASS

    if not meta_class.class_name:
        return None
    #if not (cmp(class_name, "OSObject") and cmp(class_name, "OSMetaClass")):
        #return None
    if not meta_class.class_self_addr:
        exit(2)

    if not iskext:
        const_start = k_header.macho_get_vmaddr("__DATA_CONST", "__const")
        const_start_f = k_header.macho_get_fileaddr("__DATA_CONST", "__const")

        meta_class.metaclass_vt_vm = x_metaclass_vt_vm
        meta_class.metaclass_vt_f = x_metaclass_vt_f

        mc_meth_start_f = meta_class.metaclass_vt_f
        mc_meth_addr = k_header.memcpy(mc_meth_start_f, 8)
        while mc_meth_addr:
            if mc_meth_addr in STRING_TAB:
                metaclass_name = STRING_TAB[mc_meth_addr]
            else:
                metaclass_name = "sub_" + hex(mc_meth_addr)
            meta_class.metaclass_list.append(hex(mc_meth_addr) + "\t" + metaclass_name)
            mc_meth_start_f += 8
            mc_meth_addr = k_header.memcpy(mc_meth_start_f, 8)

        # find the instance vtable
        # first: we should search it from string table
        # second: if no found, ugly, only have to search one by one
        object_name = "__ZTV%d%s" % (len(meta_class.class_name), meta_class.class_name)
        for k, v in STRING_TAB.iteritems():
            if not cmp(v, object_name):
                meta_class.object_vt_vm = k
                meta_class.object_vt_f = k_header.get_f_from_vm(const_start_f, const_start, k)
                break
        if meta_class.object_vt_vm:
            o_meth_start_f = meta_class.object_vt_f + 0x10
            o_meth_addr = k_header.memcpy(o_meth_start_f, 8)
            while o_meth_addr:
                if o_meth_addr in STRING_TAB:
                    o_meth_name = STRING_TAB[o_meth_addr]
                else:
                    o_meth_name = "sub_" + hex(o_meth_addr)
                meta_class.instance_list.append(hex(o_meth_addr) + "\t" + o_meth_name)
                o_meth_start_f += 8
                o_meth_addr = k_header.memcpy(o_meth_start_f, 8)
        else:
            # second method, but i think this make no sense
            # print "------*%s*------" % object_name
            pass

        BASE_CLASS[meta_class.class_self_addr] = meta_class

    else:
        const_start = k_header.kernel_header.macho_get_vmaddr("__PLK_DATA_CONST", "__data")
        const_start_f = k_header.kernel_header.macho_get_fileaddr("__PLK_DATA_CONST", "__data")

        meta_class.metaclass_vt_vm = x_metaclass_vt_vm
        meta_class.metaclass_vt_f = x_metaclass_vt_f

        mc_meth_start_f = meta_class.metaclass_vt_f
        mc_meth_addr = k_header.kernel_header.memcpy(mc_meth_start_f, 8)
        while mc_meth_addr:
            if mc_meth_addr in STRING_TAB:
                metaclass_name = STRING_TAB[mc_meth_addr]
            else:
                metaclass_name = "sub_" + hex(mc_meth_addr)
            meta_class.metaclass_list.append(hex(mc_meth_addr) + "\t" + metaclass_name)
            mc_meth_start_f += 8
            mc_meth_addr = k_header.kernel_header.memcpy(mc_meth_start_f, 8)

        # method as follows
        # every Class will implement the getMetaClass() function in its instance functions.
        # like:
        """
        ------110--------
        (0xfffffff00769de80)->OSMetaClass:OSMetaClass call 4 args list
        ClassName : IOSimpleReporter
        SuperClass: IOReporter-->OSObject
        ClassSize : 0x88
        0 : 0xfffffff0075b403cL           sub_0xfffffff0075b403cL                 
        1 : 0xfffffff0075b41fcL           sub_0xfffffff0075b41fcL                 
        2 : 0xfffffff0075124f4L           OSMetaClass::release()                   __ZNK11OSMetaClass7releaseEi
        3 : 0xfffffff0075124f8L           OSMetaClass::getRetainCount()            __ZNK11OSMetaClass14getRetainCountEv
        4 : 0xfffffff007512500L           OSMetaClass::retain()                    __ZNK11OSMetaClass6retainEv
        5 : 0xfffffff007512504L           OSMetaClass::release()                   __ZNK11OSMetaClass7releaseEv
        6 : 0xfffffff007512508L           OSMetaClass::serialize(OSSerialize)      __ZNK11OSMetaClass9serializeEP11OSSerialize
    ==> 7 : 0xfffffff007512528L           OSMetaClass::getMetaClass()              __ZNK11OSMetaClass12getMetaClassEv
        8 : 0xfffffff007512324L           OSMetaClassBase::isEqualTo()             __ZNK15OSMetaClassBase9isEqualToEPKS_
        9 : 0xfffffff007512534L           OSMetaClass::taggedRetain()              __ZNK11OSMetaClass12taggedRetainEPKv
        10: 0xfffffff007512538L           OSMetaClass::taggedRelease()             __ZNK11OSMetaClass13taggedReleaseEPKv
        11: 0xfffffff00751253cL           OSMetaClass::taggedRelease()             __ZNK11OSMetaClass13taggedReleaseEPKvi
        12: 0xfffffff0075b43b8L           IOSimpleReporter::MetaClass(alloc)       __ZNK16IOSimpleReporter9MetaClass5allocEv
        ------------
        0 : 0xfffffff0075b3fc4L           IOSimpleReporter::E()                    __ZN16IOSimpleReporterD1Ev
        1 : 0xfffffff0075b3fd0L           __ZN16IOSimpleReporterD0Ev               __ZN16IOSimpleReporterD0Ev
        2 : 0xfffffff007514588L           OSObject::release()                      __ZNK8OSObject7releaseEi
        3 : 0xfffffff00751459cL           OSObject::getRetainCount()               __ZNK8OSObject14getRetainCountEv
        4 : 0xfffffff0075145a4L           OSObject::retain()                       __ZNK8OSObject6retainEv
        5 : 0xfffffff0075145b4L           OSObject::release()                      __ZNK8OSObject7releaseEv
        6 : 0xfffffff0075145c4L           OSObject::serialize(OSSerialize)         __ZNK8OSObject9serializeEP11OSSerialize
    ==> 7 : 0xfffffff0075b4020L           IOSimpleReporter::getMetaClass()         __ZNK16IOSimpleReporter12getMetaClassEv
        8 : 0xfffffff007512324L           OSMetaClassBase::isEqualTo()             __ZNK15OSMetaClassBase9isEqualToEPKS_
        9 : 0xfffffff0075146acL           OSObject::taggedRetain()                 __ZNK8OSObject12taggedRetainEPKv
        10: 0xfffffff007514740L           OSObject::taggedRelease()                __ZNK8OSObject13taggedReleaseEPKv
        11: 0xfffffff007514750L           OSObject::taggedRelease()                __ZNK8OSObject13taggedReleaseEPKvi

        """
        # so, if we can location the addr of IOSimpleReporter::getMetaClass(), then we can get the class object vtable
        # by the way, the method to locate the getMetaClass() address can be here:
        # 1:  adrp x0, addr@page
        #     add x0, x0, addr@pageoff
        #     ret
        # or   (this one may not effective)
        # 2:  adr x0, ...
        #     (nop)
        #     ret

        exec_text_vmaddr   = k_header.macho_get_vmaddr("__TEXT_EXEC", "__text")
        exec_text_fileaddr = k_header.get_prelinkf_from_vm(exec_text_vmaddr)
        exec_text_size     = k_header.macho_get_size("__TEXT_EXEC", "__text")
        cs_handler = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        cs_handler.detail = True  # this is very important
        object_vt_f = 0
        object_vt_vm = 0
        for mem_f in range(exec_text_fileaddr, exec_text_fileaddr + exec_text_size, 4):
            mem_vm = k_header.get_prelinkvm_from_f(const_start, const_start_f, mem_f)
            #print hex(mem_f), hex(mem_vm)
            code = k_header.kernel_header.memcpy(mem_f, 0xc)
            cs_insn = cs_handler.disasm(code, mem_vm)
            gmc_func_addr = is_getMetaClass_func(cs_insn, meta_class)
            if gmc_func_addr:
                #print gmc_func_addr
                object_vt_f = get_object_vtable(k_header, gmc_func_addr)
                if object_vt_f:
                    object_vt_vm = k_header.get_prelinkvm_from_f(const_start, const_start_f, object_vt_f)
                break
        if object_vt_f and object_vt_vm:
            meta_class.object_vt_vm = object_vt_vm
            meta_class.object_vt_f = object_vt_f
            o_meth_start_f = object_vt_f
            o_meth_addr = k_header.kernel_header.memcpy(o_meth_start_f, 8)
            while o_meth_addr:
                if o_meth_addr in STRING_TAB:
                    o_meth_name = STRING_TAB[o_meth_addr]
                else:
                    o_meth_name = "sub_" + hex(o_meth_addr)
                meta_class.instance_list.append(hex(o_meth_addr) + "\t" + o_meth_name)
                o_meth_start_f += 8
                o_meth_addr = k_header.kernel_header.memcpy(o_meth_start_f, 8)
        else:
            # second method, but i think this make no sense
            # print "------*%s*------" % object_name
            pass

        DRIVER_CLASS[meta_class.class_self_addr] = meta_class
        #print DRIVER_CLASS


def get_object_vtable(k_header, gmc_func_addr):
    # gmc = getmetaclass()
    data_const_vmaddr = k_header.macho_get_vmaddr("__DATA_CONST", "__const")
    data_const_f = k_header.get_prelinkf_from_vm(data_const_vmaddr)
    data_const_size = k_header.macho_get_size("__DATA_CONST", "__const")
    for mem_f in range(data_const_f + 7*0x8, data_const_f + data_const_size, 0x8):
        addr = k_header.kernel_header.memcpy(mem_f, 0x8)
        #print hex(mem_f), addr
        if addr == gmc_func_addr:
            check1 = k_header.kernel_header.memcpy(mem_f - 0x8*(7+1), 0x8)
            check2 = k_header.kernel_header.memcpy(mem_f - 0x8*(7+2), 0x8)
            if not (check1 or check2):
                return mem_f-0x8*7
    return None


def is_getMetaClass_func(cs_insn, meta_class):
    insns = list()
    for insn in cs_insn:
        insns.append(insn)

    if len(insns) != 3:
        return None

    if not cmp(insns[0].mnemonic, "adrp"):
        if not cmp(insns[1].mnemonic, "add"):
            if not cmp(insns[2].mnemonic, "ret"):
                insn0_imm = get_single_IMM(insns[0])
                insn1_imm = get_single_IMM(insns[1])
                getMetaClass_addr = int(insn0_imm, 16) + int(insn1_imm, 16)
                if getMetaClass_addr == meta_class.class_self_addr:
                    return insns[0].address

    if not cmp(insns[0].mnemonic, "adr"):
        if not cmp(insns[1].mnemonic, "ret"):
            print "asdfasdf"
            print insns[1].address

        elif not cmp(insns[1].mnemonic, "nop"):
            print "dddddddd"
            print insns[1].address

    return None



def get_jump_addr(k_header, cs_handler, bl_addr_vm, bl_addr_f):
    code = k_header.memcpy(bl_addr_f, 0xfff)
    cs_insn = cs_handler.disasm(code, bl_addr_vm)
    first_check = 1
    for insn in cs_insn:
        address = insn.address
        mnemonic = insn.mnemonic
        op_str = insn.op_str
        # print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))

        if first_check:
            if not (cmp(mnemonic, "adrp") and cmp(mnemonic, "adr")):
                is_x16_reg = get_first_reg(insn)
                if is_x16_reg != arm64_const.ARM64_REG_X16:
                    return 0

        if not (cmp(mnemonic, "adrp") and cmp(mnemonic, "adr")):
            imm = get_single_IMM(insn)
            seg_num = insn.op_count(CS_OP_REG)
            if seg_num > 2:
                print "Extract: too many regs!"
            index = insn.op_find(CS_OP_REG, 1)
            s_reg = index.value.reg
            set_actual_value_by_regN(s_reg, eval(imm))

        if not cmp(mnemonic, "ldr"):
            reg_num = insn.op_count(CS_OP_REG)
            if reg_num == 1:
                imem_num = insn.op_count(CS_OP_MEM)
                if imem_num:
                    mem_offset = get_mem_op_offset(insn)
                    x16_reg = get_mem_op_reg(insn)
                    x16_reg_v = get_actual_value_by_regN(x16_reg)
                    set_actual_value_by_regN(x16_reg, x16_reg_v + mem_offset)
                    try:
                        x16_reg_mem_v = k_header.get_mem_from_vmaddr(bl_addr_f, bl_addr_vm,
                                                                     get_actual_value_by_regN(x16_reg))
                        set_actual_value_by_regN(x16_reg, x16_reg_mem_v)
                    except:
                        return 0

        if not cmp(mnemonic, "br"):
            if insn.op_count(CS_OP_REG):
                is_x16_reg = get_first_reg(insn)
                if is_x16_reg == arm64_const.ARM64_REG_X16:
                    return get_actual_value_by_regN(is_x16_reg)
            break
    return 0


def analysis_inheritance_base(iskext, debug):
    global BASE_CLASS
    global DRIVER_CLASS
    global IOUserClient_VMaddr
    global META_CLASSES

    if iskext:
        index = 0
        print DRIVER_CLASS
        for class_self, meta_class in DRIVER_CLASS.iteritems():
            super_addr = meta_class.class_super_addr
            super_class_name = ""
            while True:
                if super_addr in META_CLASSES:
                    super_class_name = super_class_name + META_CLASSES[super_addr].class_name
                    super_class_name += "-->"
                    meta_class.class_super_list.append(META_CLASSES[super_addr].class_self_addr)
                    super_addr = META_CLASSES[super_addr].class_super_addr
                elif super_addr in DRIVER_CLASS:
                    super_class_name = super_class_name + DRIVER_CLASS[super_addr].class_name
                    super_class_name += "-->"
                    meta_class.class_super_list.append(DRIVER_CLASS[super_addr].class_self_addr)
                    super_addr = DRIVER_CLASS[super_addr].class_super_addr
                elif super_addr in BASE_CLASS:
                    super_class_name = super_class_name + BASE_CLASS[super_addr].class_name
                    super_class_name += "-->"
                    meta_class.class_super_list.append(BASE_CLASS[super_addr].class_self_addr)
                    super_addr = BASE_CLASS[super_addr].class_super_addr
                else:
                    if "-->" in super_class_name:
                        super_class_name = super_class_name[:-3]
                    break

            meta_class.class_super_name = super_class_name

            # print the debug info
            if debug:
                print
                print "------%d--------" % index
                print "(0x%x)->OSMetaClass:OSMetaClass call 4 args list" % meta_class.class_self_addr
                # print "ClassName:0x%x" % meta_class.class_self_addr
                print "ClassName : %s" % meta_class.class_name
                if meta_class.class_super_addr:
                    print "SuperClass: %s" % meta_class.class_super_name
                #else:
                print "SuperClass: 0x%x" % meta_class.class_super_addr
                print "ClassSize : 0x%x" % meta_class.class_size
                # print meta_class.class_super_list
                printfunc(meta_class)

            index += 1
    else:
        index = 0
        for class_self, meta_class in BASE_CLASS.iteritems():
            super_addr = meta_class.class_super_addr
            super_class_name = ""
            while True:
                if super_addr in BASE_CLASS:
                    super_class_name = super_class_name + BASE_CLASS[super_addr].class_name
                    super_class_name += "-->"
                    meta_class.class_super_list.append(BASE_CLASS[super_addr].class_self_addr)
                    super_addr = BASE_CLASS[super_addr].class_super_addr
                else:
                    if "-->" in super_class_name:
                        super_class_name = super_class_name[:-3]
                    break

            meta_class.class_super_name = super_class_name

            # print the debug info
            if debug:
                print
                print "------%d--------" % index
                print "(0x%x)->OSMetaClass:OSMetaClass call 4 args list" % meta_class.class_self_addr
                #print "ClassName:0x%x" % meta_class.class_self_addr
                print "ClassName : %s" % meta_class.class_name
                print "SuperClass: %s" % meta_class.class_super_name
                print "ClassSize : 0x%x" % meta_class.class_size
                printfunc(meta_class)
            index += 1


def printfunc(meta_class):
    global BASE_CLASS
    global DRIVER_CLASS

    index = 0
    for func in meta_class.metaclass_list:
        func_addr = func.split("\t")[0]
        func_name = func.split("\t")[1]
        if "sub_" in func_name:
            print "%-3d: %-25s%-40s" % (index, func_addr, func_name)
            index += 1
            continue
        if "IOUserClient" in func_name:
            highlight = "%-3d: %-25s%-40s" % (index, func_addr, type_parser(func_name))
            printRed(highlight)
        else:
            print "%-3d: %-25s%-40s" % (index, func_addr, type_parser(func_name))
        index += 1

    if "IOService" in meta_class.class_super_name:
        print "-----vtable:%s-------" % hex(meta_class.object_vt_vm)

        # print class title
        title = "%-3s  %-25s%-60s" % (" ", " ", meta_class.class_name)
        for j in range(len(meta_class.class_super_list)):
            super_addr = meta_class.class_super_list[j]
            super_c = None
            if super_addr in DRIVER_CLASS:
                super_c = DRIVER_CLASS[super_addr]
            if super_addr in BASE_CLASS:
                super_c = BASE_CLASS[super_addr]
            if super_c:
                super_c_n = "%-60s" % super_c.class_name
                title += super_c_n
        print title

        # join the method name string
        index = 0
        for i in range(len(meta_class.instance_list)):
            instance_addr = meta_class.instance_list[i].split("\t")[0]
            instance_name = meta_class.instance_list[i].split("\t")[1]
            if "sub_" in instance_name:
                print_str = "%-3d: %-25s%-60s" % (index, instance_addr, instance_name)
            elif "IOUserClient" in instance_name:
                print_str = "%-3d: %-25s%-60s" % (index, instance_addr, type_parser(instance_name))
            else:
                print_str = "%-3d: %-25s%-60s" % (index, instance_addr, type_parser(instance_name))

            for j in range(len(meta_class.class_super_list)):
                super_addr = meta_class.class_super_list[j]
                if super_addr in DRIVER_CLASS:
                    super_c = DRIVER_CLASS[super_addr]
                    if i < len(super_c.instance_list):
                        super_inst = super_c.instance_list[i].split("\t")[1]
                        if "sub_" not in super_inst:
                            super_inst = type_parser(super_inst)
                        super_str = "%-60s" % super_inst
                        print_str += super_str
                if super_addr in BASE_CLASS:
                    super_c = BASE_CLASS[super_addr]
                    if i < len(super_c.instance_list):
                        super_inst = super_c.instance_list[i].split("\t")[1]
                        if "sub_" not in super_inst:
                            super_inst = type_parser(super_inst)
                        super_str = "%-60s" % super_inst
                        print_str += super_str

            if "IOUserClient" in print_str:
                printRed(print_str)
            else:
                print print_str
            index += 1
    else:
        print "-----vtable:%s-------" % hex(meta_class.object_vt_vm)
        index = 0
        for instance in meta_class.instance_list:
            instance_addr = instance.split("\t")[0]
            instance_name = instance.split("\t")[1]
            if "sub_" in instance_name:
                print "%-3d: %-25s%-60s" % (index, instance_addr, instance_name)
                index += 1
                continue
            if "IOUserClient" in instance_name:
                highlight = "%-3d: %-25s%-60s" % (index, instance_addr, type_parser(instance_name))
                printRed(highlight)
            else:
                #print instance
                print "%-3d: %-25s%-60s" % (index, instance_addr, type_parser(instance_name))
            index += 1


def analysis_mif_kext(kernel_header, kernel_f, kexts):
    global prelink_kext_vm
    global prelink_kext_f
    global prelink_kext_size

    if not isinstance(kexts, list):
        print "bad kexts args"
        return
    # used to calculate the file offset
    prelink_f_offset = prelink_kext_vm - prelink_kext_f
    # print hex(prelink_kext_vm), hex(prelink_kext_f), prelink_kext_size

    driver_list_p, driver_list_np = kernel_header.get_driver_list()
    if not cmp(kexts[0], "all"):
        index = 1
        total_k = len(driver_list_p)
        for kext_name, kext_vm in driver_list_p.iteritems():
            print "(%d/%d)-------%s---------" % (index, total_k, kext_name)
            if kext_name in ["com.apple.driver.AppleT8015CLPC", "com.apple.filesystems.hfs.kext"]:
                continue
            # init kext_header
            kext_vm = int(kext_vm, 16)
            kext_f = kext_vm - prelink_f_offset
            kext_header = init_kext_header(kernel_f, kext_f)
            kext_header.prelink_offset = prelink_f_offset
            kext_header.kernel_header = kernel_header

            analysis_mif(kext_header, True)

    else:
        for kext in kexts:
            if kext in driver_list_np:
                print "Parser: no need to parse!"
                exit(2)
            if kext not in driver_list_p:
                print "Parser: kext not found!"
                exit(2)

            # init kext_header
            kext_vm = int(driver_list_p[kext], 16)
            kext_f = kext_vm - prelink_f_offset
            kext_header = init_kext_header(kernel_f, kext_f)
            kext_header.prelink_offset = prelink_f_offset
            kext_header.kernel_header = kernel_header

            analysis_mif(kext_header, True)

        # get all meta class for inheritance analysis
        # we don't do this again when kext is 'all'
        get_metaclass(kernel_header, kernel_f)

        global META_CLASSES
        global BASE_CLASS
        with open("MetaClass.txt", 'w') as metaclass:
            for mc_addr, mc in META_CLASSES.iteritems():
                if mc_addr in BASE_CLASS:
                    continue
                metaclass.write('"' + mc.class_name + '"')
                metaclass.write(",\n")


def get_metaclass(kernel_header, kernel_f):
    global prelink_kext_vm
    global prelink_kext_f
    global prelink_kext_size

    get_all_metaclass(kernel_header, False)

    # used to calculate the file offset
    prelink_f_offset = prelink_kext_vm - prelink_kext_f

    driver_list_p, driver_list_np = kernel_header.get_driver_list()
    index = 1
    total_k = len(driver_list_p)
    for kext_name, kext_vm in driver_list_p.iteritems():
        print "(%d/%d)-------%s---------" % (index, total_k, kext_name)
        index += 1
        if kext_name in ["com.apple.driver.AppleT8015CLPC", "com.apple.filesystems.hfs.kext"]:
            continue
        # init kext_header
        kext_vm = int(kext_vm, 16)
        kext_f = kext_vm - prelink_f_offset
        kext_header = init_kext_header(kernel_f, kext_f)
        kext_header.prelink_offset = prelink_f_offset
        kext_header.kernel_header = kernel_header

        get_all_metaclass(kext_header, True)


def getSubIOServicesClass(kernel_f, sub_ioservice):
    k_header = init_kernel_header(kernel_f)
    prepare_string(k_header)
    prepare_offset(k_header)
    setup_OSMetaClassFunc(k_header)

    analysis_mif(k_header)
    analysis_inheritance_base(False, False)

    analysis_mif_kext(k_header, kernel_f, sub_ioservice)
    analysis_inheritance_base(True, True)


def getAllMetaClass(kernel_f):
    k_header = init_kernel_header(kernel_f)
    get_metaclass(k_header, kernel_f)
    global META_CLASSES
    with open("MetaClass.txt", 'r') as metaclass:
        for mc, key in META_CLASSES.iteritems():
            metaclass.write(key)
            metaclass.write("\n")


if __name__ == '__main__':
    #
    #getSubIOServicesClass("/home/wdy/ipsw/iphonex/11_2_2/kernel_x", "com.apple.iokit.IOHIDFamily")
    #getSubIOServicesClass("/home/wdy/ipsw/iphonex/11_2_2/kernel_x", "com.apple.iokit.IOHIDFamily")
    #getSubIOServicesClass("/home/wdy/Desktop/kernel_10_3_2", ["com.apple.iokit.IOHIDFamily"])
    getSubIOServicesClass("/home/wdy/Desktop/kernel_13", ["com.apple.iokit.IOHIDFamily"])
    #getSubIOServicesClass("/Users/lilang_wu/Documents/vulnerabilities/macOS/p-joker/p-joker-dev-v1.1/kernelcache.decrypted", ["com.apple.driver.AppleMobileDispH10P",
     #                                                                "com.apple.iokit.IOMobileGraphicsFamily"])
    #getSubIOServicesClass("/home/wdy/ipsw/kernel_cache/kernel_10_3_2", "com.apple.iokit.IONetworkingFamily")
    #getSubIOServicesClass("/home/wdy/ipsw/kernel_cache/kernel_10_3_2", "all")
    #getSubIOServicesClass("/home/wdy/ipsw/iphonex/11_2_2/kernel_x", "all")
    #getAllMetaClass("/home/wdy/ipsw/iphonex/11_2_2/kernel_x")
    #print len(DRIVER_CLASS) + len(BASE_CLASS)
