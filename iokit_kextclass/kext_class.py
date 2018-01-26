
import os
import sys
sys.path.append("../")
from kernel.offset import MachOHeader
from kernel.kernel import KernelMachO
from capstone import *
from xprint import to_hex, to_x
from regs import *
from OSMetaClass import OSMetaClass

OSMetaClass_OSMetaClass_VMaddr = 0
IOUserClient_VMaddr = 0
IOService_VMaddr = 0

STRING_TAB = {}

BASE_CLASS = {}
DRIVER_CLASS = {}


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


def analysis_mif(k_header=None, iskext=False):  # mod init func
    global IOUserClient_VMaddr
    global IOService_VMaddr

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
                    imem_num = insn.op_count(CS_OP_MEM)
                    if imem_num:
                        mem_offset = get_mem_op_offset(insn)
                        x_reg = get_mem_op_reg(insn)
                        x_reg_v = get_actual_value_by_regN(x_reg)
                        set_actual_value_by_regN(x_reg, x_reg_v + mem_offset)

                        x_reg_mem_v = k_header.get_mem_from_vmaddr(each_mif_f, each_mif_vm,
                                                                     get_actual_value_by_regN(x_reg))
                        set_actual_value_by_regN(x_reg, x_reg_mem_v)

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
                if reg_num == 1:
                    continue
                f_reg = get_first_reg(insn)
                if f_reg == arm64_const.ARM64_REG_XZR:
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
        text_start = k_header.macho_get_vmaddr("__TEXT_EXEC", "__text")
        text_end = text_start + k_header.macho_get_size("__TEXT_EXEC", "__text")
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
            mc_meth_start_f += 8
            mc_meth_addr = k_header.memcpy(mc_meth_start_f, 8)
            meta_class.metaclass_list.append(metaclass_name)

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
                o_meth_start_f += 8
                o_meth_addr = k_header.memcpy(o_meth_start_f, 8)
                meta_class.instance_list.append(o_meth_name)
        else:
            # second method, but i think this make no sense
            # print "------*%s*------" % object_name
            pass

        BASE_CLASS[meta_class.class_self_addr] = meta_class

    else:
        text_start = k_header.kernel_header.macho_get_vmaddr("__PLK_TEXT_EXEC", "__text")
        text_end = text_start + k_header.kernel_header.macho_get_size("__PLK_TEXT_EXEC", "__text")
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
            mc_meth_start_f += 8
            mc_meth_addr = k_header.kernel_header.memcpy(mc_meth_start_f, 8)
            meta_class.metaclass_list.append(metaclass_name)
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
                o_meth_start_f += 8
                o_meth_addr = k_header.memcpy(o_meth_start_f, 8)
                meta_class.instance_list.append(o_meth_name)
        else:
            # second method, but i think this make no sense
            # print "------*%s*------" % object_name
            pass

        DRIVER_CLASS[meta_class.class_self_addr] = meta_class

def get_jump_addr(k_header, cs_handler, bl_addr_vm, bl_addr_f):
    code = k_header.memcpy(bl_addr_f, 0xfff)
    cs_insn = cs_handler.disasm(code, bl_addr_vm)
    first_check = 1
    for insn in cs_insn:
        address = insn.address
        mnemonic = insn.mnemonic
        op_str = insn.op_str
        #print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))

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

                    x16_reg_mem_v = k_header.get_mem_from_vmaddr(bl_addr_f, bl_addr_vm,
                                                                 get_actual_value_by_regN(x16_reg))
                    set_actual_value_by_regN(x16_reg, x16_reg_mem_v)

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

    if iskext:
        index = 0
        for class_self, meta_class in DRIVER_CLASS.iteritems():
            super_addr = meta_class.class_super_addr
            super_class_name = ""
            while True:
                if super_addr in DRIVER_CLASS:
                    super_class_name = super_class_name + DRIVER_CLASS[super_addr].class_name
                    super_class_name += "-->"
                    super_addr = DRIVER_CLASS[super_addr].class_super_addr
                elif super_addr in BASE_CLASS:
                    super_class_name = super_class_name + BASE_CLASS[super_addr].class_name
                    super_class_name += "-->"
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
                #print meta_class.metaclass_list
                #print len(meta_class.metaclass_list)
                #print meta_class.instance_list
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
                #print len(meta_class.metaclass_list)
                #print meta_class.instance_list
            index += 1



def analysis_mif_kext(kernel_header, kernel_f, kext):
    prelink_kext_vm   = kernel_header.macho_get_vmaddr("__PRELINK_TEXT", "")
    prelink_kext_f    = kernel_header.macho_get_fileaddr("__PRELINK_TEXT", "")
    prelink_kext_size = kernel_header.macho_get_size("__PRELINK_TEXT", "")

    # used to calculate the file offset
    prelink_f_offset = prelink_kext_vm - prelink_kext_f

    print hex(prelink_kext_vm), hex(prelink_kext_f), prelink_kext_size

    driver_list_p, driver_list_np = kernel_header.get_driver_list()
    if not cmp(kext, "all"):
        for kext_name, kext_vm in driver_list_p.iteritems():
            print "-------%s---------" % kext_name
            # init kext_header
            kext_vm = int(kext_vm, 16)
            kext_f = kext_vm - prelink_f_offset
            kext_header = init_kext_header(kernel_f, kext_f)
            kext_header.prelink_offset = prelink_f_offset
            kext_header.kernel_header = kernel_header

            analysis_mif(kext_header, True)

    else:
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





def getSubIOServicesClass(kernel_f, sub_ioservice):
    k_header = init_kernel_header(kernel_f)
    prepare_string(k_header)
    setup_OSMetaClassFunc(k_header)

    analysis_mif(k_header)
    analysis_inheritance_base(False, False)

    analysis_mif_kext(k_header, kernel_f, sub_ioservice)
    analysis_inheritance_base(True, True)



if __name__ == '__main__':

    getSubIOServicesClass("/home/wdy/ipsw/kernel_cache/kernel_10_3_2", "com.apple.iokit.IOUSBDeviceFamily")
    #getSubIOServicesClass("/home/wdy/ipsw/kernel_cache/kernel_10_3_2", "com.apple.iokit.IONetworkingFamily")
    #getSubIOServicesClass("/home/wdy/ipsw/kernel_cache/kernel_10_3_2", "all")