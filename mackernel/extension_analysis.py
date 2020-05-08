
import sys
import struct

sys.path.append("../")

from capstone import *
from capstone import x86_const

from iokit_kextclass.print_xformat import to_hex, to_x
from iokit_kextclass.OSMetaClass import *
from kernel.offset import MachOHeader

from arm_regs import x_reg_manager
from mach_struct import *
from misc_func import *
from global_info import *

from iokitconnection import IOKitConnection



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


def init_kernel_header(kernel_f):
    macho_file = open(kernel_f, "rb")
    macho_file.seek(0, 2)
    size = macho_file.tell()
    macho_file.seek(0)
    return MachOHeader(macho_file, 0, size)


def prepare_string(k_header):
    global STRING_TAB
    global SYMBOL_TAB
    global SECTION_INDEX

    string_table_f    = k_header.macho_get_fileaddr("__STRINGTAB", "")
    string_table_size = k_header.macho_get_size("__STRINGTAB", "")
    symbol_table_f    = k_header.macho_get_fileaddr("__SYMTAB", "")
    sym_num           = k_header.macho_get_size("__SYMTAB", "")

    # print hex(string_table_f), hex(string_table_size), hex(symbol_table_f)

    offset = symbol_table_f
    for i in range(sym_num):
        index     = k_header.memcpy(offset, 4)
        sec_index = k_header.memcpy(offset + 5, 1)
        addr      = k_header.memcpy(offset + 8, 8)
        string    = k_header.get_memStr_from_f(string_table_f + index)

        STRING_TAB[addr]    = string
        SYMBOL_TAB[i]       = string
        SECTION_INDEX[addr] = sec_index

        offset += 16


def prepare_external_relocations(k_header):
    global EXT_RELOCATIONS
    global SYMBOL_TAB

    ext_reloc_f    = k_header.macho_get_fileaddr("__DYSYMTAB", "")
    ext_reloc_size = k_header.macho_get_size("__DYSYMTAB", "")

    offset = ext_reloc_f
    for i in range(ext_reloc_size):
        er_item = Ext_Reloc()
        er_item.construct_ExtReloc(k_header.memcpy(offset, 8))
        EXT_RELOCATIONS[er_item.r_address] = SYMBOL_TAB[er_item.r_symbol_index]
        offset += 8


def prepare_static_vars():
    # these static vars may be the IOExternalMethodDispatch object which contains all the selectors info
    global USER_CLIENT_METHODS
    global STRING_TAB

    for er_item_addr, er_item in STRING_TAB.iteritems():
        if er_item.startswith("__ZZ") and "UserClient" in er_item:
            USER_CLIENT_METHODS[er_item_addr] = er_item


def prepare_loadcmds(k_header):
    global LOAD_CMDS_TAB
    lc_tab = k_header.macho_get_loadcmds()
    for key, v in lc_tab.iteritems():
        LOAD_CMDS_TAB[key] = v


def get_OSMetaClass_initFunc(k_header):
    global STRING_TAB
    global EXT_RELOCATIONS
    global META_CLASSES

    base_vmaddr =       k_header.macho_get_vmaddr("__TEXT", None)
    mod_init_vmaddr =   k_header.macho_get_vmaddr("__DATA", "__mod_init_func")
    mod_init_fileaddr = k_header.macho_get_fileaddr("__DATA", "__mod_init_func")
    mod_init_size =     k_header.macho_get_size("__DATA", "__mod_init_func")

    const_vmaddr =   k_header.macho_get_vmaddr("__TEXT", "__const")
    const_fileaddr = k_header.macho_get_fileaddr("__TEXT", "__const")
    const_size =     k_header.macho_get_size("__TEXT", "__const")


    total_mif = mod_init_size / 8
    # print "Extract: total %d kernel base object modinit" % total_mif

    for i in range(0, total_mif):
        each_mif_vm = k_header.get_mem_from_vmaddr(mod_init_fileaddr, mod_init_vmaddr, mod_init_vmaddr + i * 8)
        each_mif_f = k_header.get_f_from_vm(mod_init_fileaddr, mod_init_vmaddr, each_mif_vm)

        #print each_mif_vm, hex(each_mif_vm)
        #print each_mif_f, hex(each_mif_f)

        cs_handler = Cs(CS_ARCH_X86, CS_MODE_LITTLE_ENDIAN)
        cs_handler.detail = True  # this is very important
        code = k_header.memcpy(each_mif_f, 0x3ff)
        cs_insn = cs_handler.disasm(code, each_mif_vm)
        xr_m = x_reg_manager()

        for insn in cs_insn:
            address = insn.address
            mnemonic = insn.mnemonic
            op_str = insn.op_str

            # print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))

            xr_m.set_actual_value_by_regN(x86_const.X86_REG_RIP, address + insn.size)

            if not cmp(mnemonic, "lea"):
                seg_num = insn.op_count(CS_OP_REG)
                if seg_num > 2:
                    print "Extract: too many regs!"

                imem_num = insn.op_count(CS_OP_MEM)
                if imem_num:
                    mem_offset = get_mem_op_offset(insn)

                    s_reg = get_mem_op_reg(insn)
                    if s_reg == x86_const.X86_REG_RIP:
                        s_reg_v = xr_m.get_actual_value_by_regN(x86_const.X86_REG_RIP)
                        mem_addr = mem_offset + s_reg_v

                        index = insn.op_find(CS_OP_REG, 1)
                        f_reg = index.value.reg
                        xr_m.set_actual_value_by_regN(f_reg, mem_addr)

            if not cmp(mnemonic, "mov"):
                seg_num = insn.op_count(CS_OP_REG)
                if seg_num > 2:
                    print "Extract: too many regs!"

                imem_num = insn.op_count(CS_OP_MEM)
                # print "imem_num = %d" % imem_num
                if imem_num:
                    mem_offset = get_mem_op_offset(insn)
                    s_reg = get_mem_op_reg(insn)
                    if s_reg == x86_const.X86_REG_RIP:
                        s_reg_v = xr_m.get_actual_value_by_regN(x86_const.X86_REG_RIP)
                        mem_addr = mem_offset + s_reg_v
                        try:
                            index = insn.op_find(CS_OP_REG, 1)
                            f_reg = index.value.reg
                            xr_m.set_actual_value_by_regN(f_reg, mem_addr)
                        except:
                            pass
                        continue

                imm_num = insn.op_count(CS_OP_IMM)
                # print "imm_num = %d" % imm_num
                if imm_num == 1:
                    imm = get_single_IMM(insn)
                    try:
                        index = insn.op_find(CS_OP_REG, 1)
                        s_reg = index.value.reg
                        xr_m.set_actual_value_by_regN(s_reg, imm)
                    except:
                        pass
                    continue

                if seg_num == 2:
                    try:
                        f_reg = get_first_reg(insn)
                        s_reg = get_second_reg(insn)
                        xr_m.set_actual_value_by_regN(f_reg, xr_m.get_actual_value_by_regN(s_reg))
                    except:
                        pass
                continue

            if not cmp(mnemonic, "call"):
                imm_num = insn.op_count(CS_OP_IMM)
                if imm_num == 1:
                    #address_f = k_header.get_f_from_vm(mod_init_fileaddr, mod_init_vmaddr, address)
                    cf_addr = address + 1
                    if cf_addr in EXT_RELOCATIONS:
                        if EXT_RELOCATIONS[cf_addr] == "__ZN11OSMetaClassC2EPKcPKS_j":
                            meta_class = OSMetaClass()
                            meta_class.class_self_addr  = xr_m.get_actual_value_by_regN(x86_const.X86_REG_RDI)
                            meta_class.class_name_addr  = xr_m.get_actual_value_by_regN(x86_const.X86_REG_RSI)
                            meta_class.class_super_addr = xr_m.get_actual_value_by_regN(x86_const.X86_REG_RDX)
                            meta_class.class_size       = xr_m.get_actual_value_by_regN(x86_const.X86_REG_ECX)

                            if meta_class.class_name_addr:
                                # get meta class name
                                meta_class.class_name = k_header.get_memStr_from_vmaddr(each_mif_f, each_mif_vm,
                                                                                        meta_class.class_name_addr)
                                # get vtable for AppleClass*
                                object_name = "__ZTV%d%s" % (len(meta_class.class_name), meta_class.class_name)
                                for k, v in STRING_TAB.iteritems():
                                    if not cmp(v, object_name):
                                        meta_class.object_vt_vm = k
                                        meta_class.object_vt_f = k_header.get_f_from_vm(const_fileaddr, const_vmaddr, k)
                                        break

                                # get vtable for AppleClass*::MetaClass
                                meta_name = "__ZTVN%d%s%d%sE" % (len(meta_class.class_name), meta_class.class_name,
                                                                  len("MetaClass"), "MetaClass")
                                for k, v in STRING_TAB.iteritems():
                                    if not cmp(v, meta_name):
                                        meta_class.metaclass_vt_vm = k
                                        meta_class.metaclass_vt_f = k_header.get_f_from_vm(const_fileaddr, const_vmaddr, k)
                                        break

                            else:
                                meta_class.class_name = "unknow classname"

                            #print "meta_class.super_addr = %d, %x" % (meta_class.class_super_addr, meta_class.class_super_addr)
                            if meta_class.class_super_addr:
                                if meta_class.class_super_addr in EXT_RELOCATIONS:
                                    meta_class.class_super_name = EXT_RELOCATIONS[meta_class.class_super_addr]
                                elif meta_class.class_super_addr in STRING_TAB:
                                    meta_class.class_super_name = STRING_TAB[meta_class.class_super_addr]
                                else:
                                    meta_class.class_super_name = k_header.get_memStr_from_vmaddr(each_mif_f, each_mif_vm,
                                                                                        meta_class.class_super_addr)
                                if meta_class.class_super_name.startswith("__ZN"):
                                    meta_class.class_super_name = demangle(meta_class.class_super_name)


                            META_CLASSES[meta_class.class_self_addr] = meta_class
                            # print hex(meta_class.metaclass_vt_vm), hex(meta_class.object_vt_vm), meta_class.class_name, meta_class.class_super_name

                            continue

            if mnemonic in ["ret"]:
                break
        #break


def analysis_need_funcs_addr(k_header):
    """
    get the addr for the following functions:
        1): ****::newUserClient()
        2): ****::getTargetAndMethodForIndex()
        3): ****::getAsyncTargetAndMethodForIndex()
        4): ****::getTargetAndTrapForIndex()
        5): ****::externalMethod()
    """
    const_vmaddr   = k_header.macho_get_vmaddr("__TEXT", "__const")
    const_fileaddr = k_header.macho_get_fileaddr("__TEXT", "__const")

    for meta_class_addr, meta_class in META_CLASSES.iteritems():
        if meta_class.can_ser_open == 1:
            clazz_name = "__ZN%d%s" % (len(meta_class.class_name), meta_class.class_name)
            newUserClient                   = clazz_name + ("%d%s" % (13, "newUserClient"))
            externalMethod                  = clazz_name + ("%d%s" % (14, "externalMethod"))
            getTargetAndMethodForIndex      = clazz_name + ("%d%s" % (26, "getTargetAndMethodForIndex"))
            getAsyncTargetAndMethodForIndex = clazz_name + ("%d%s" % (31, "getAsyncTargetAndMethodForIndex"))
            getTargetAndTrapForIndex        = clazz_name + ("%d%s" % (24, "getTargetAndTrapForIndex"))

            v_func_f = meta_class.object_vt_f + 0x10
            v_func_vm = meta_class.object_vt_vm + 0x10
            v_func_addr = k_header.memcpy(v_func_f, 8)
            v_func_name = ""
            br_sig = 0
            while True:
                """
                two situations:
                    1. v_func_addr is null, this may be the break signal, or the virturl function is extend from
                       its super class, and can be judge by index v_func_vm in above two globle TABLE
                    2. v_func_addr is not null, all functions are implement by this metaclass itself.
                """
                if v_func_addr:
                    # the v_func_addr is not null and
                    if v_func_addr in EXT_RELOCATIONS:
                        v_func_name = EXT_RELOCATIONS[v_func_addr]
                    elif v_func_addr in STRING_TAB:
                        v_func_name = STRING_TAB[v_func_addr]
                    else:
                        v_func_name = "sub_" + hex(v_func_addr)

                else:
                    # the v_func_addr is null but can be
                    if v_func_vm in EXT_RELOCATIONS:
                        v_func_name = EXT_RELOCATIONS[v_func_vm]
                    elif v_func_vm in STRING_TAB:
                        v_func_name = STRING_TAB[v_func_vm]
                    else:
                        br_sig += 1

                if newUserClient in v_func_name:
                    meta_class.newUserClient_f = k_header.get_f_from_vm(const_fileaddr, const_vmaddr, v_func_addr)
                    meta_class.newUserClient_vm = v_func_addr
                elif externalMethod in v_func_name:
                    meta_class.externalMethod_f = k_header.get_f_from_vm(const_fileaddr, const_vmaddr, v_func_addr)
                    meta_class.externalMethod_vm = v_func_addr
                elif getTargetAndMethodForIndex in v_func_name:
                    meta_class.getTargetAndMethodForIndex_f = k_header.get_f_from_vm(const_fileaddr, const_vmaddr, v_func_addr)
                    meta_class.getTargetAndMethodForIndex_vm = v_func_addr
                elif getAsyncTargetAndMethodForIndex in v_func_name:
                    meta_class.getAsyncTargetAndMethodForIndex_f = k_header.get_f_from_vm(const_fileaddr, const_vmaddr, v_func_addr)
                    meta_class.getAsyncTargetAndMethodForIndex_vm = v_func_addr
                elif getTargetAndTrapForIndex in v_func_name:
                    meta_class.getTargetAndTrapForIndex_f = k_header.get_f_from_vm(const_fileaddr, const_vmaddr, v_func_addr)
                    meta_class.getTargetAndTrapForIndex_vm = v_func_addr

                if br_sig == 2:
                    # print "Analysis newUserClient: not found newUserClient method, may be implement by its child class"
                    break

                v_func_f += 8
                v_func_vm += 8
                v_func_addr = k_header.memcpy(v_func_f, 8)
                #print v_func_addr


def check_effect_service():
    global META_CLASSES
    global USERSPACE_SERVICES

    count = 0
    iokit_instance = IOKitConnection("IOKitServices")
    for meta_class_addr, meta_class in META_CLASSES.iteritems():
        for i in range(0, 100, 1):
            connection = iokit_instance.fuzz_IOServiceOpen(meta_class.class_name, i)
            if not connection:
                meta_class.can_ser_open = 1
                meta_class.can_ser_open_type = i
                count += 1
                break
    USERSPACE_SERVICES["opened"] = count


def analysis_inheritance_base():
    global META_CLASSES
    global EXT_RELOCATIONS

    for class_self, meta_class in META_CLASSES.iteritems():
        super_addr = meta_class.class_super_addr
        extends_rela = ""
        while True:
            if super_addr in META_CLASSES:
                extends_rela = META_CLASSES[super_addr].class_name + extends_rela
                extends_rela = "-->" + extends_rela
                meta_class.class_super_list.append(META_CLASSES[super_addr].class_self_addr)
                if super_addr == META_CLASSES[super_addr].class_super_addr:
                    break
                else:
                    super_addr = META_CLASSES[super_addr].class_super_addr
            elif super_addr in EXT_RELOCATIONS:
                extends_rela = demangle(EXT_RELOCATIONS[super_addr]) + extends_rela
                extends_rela = "-->" + extends_rela
                meta_class.class_super_list.append(super_addr)
                break

        if "-->" in extends_rela:
            extends_rela = extends_rela[3:]
            extends_rela = extends_rela + "-->" +  meta_class.class_name

        meta_class.extends_list = extends_rela


def extension_analysis(kext_MachO_f):
    global META_CLASSES
    global STRING_TAB
    global SYMBOL_TAB
    global SECTION_INDEX
    global LOAD_CMDS_TAB
    global EXT_RELOCATIONS
    global USER_CLIENT_METHODS
    global USERSPACE_SERVICES

    META_CLASSES.clear()
    STRING_TAB.clear()
    SYMBOL_TAB.clear()
    SECTION_INDEX.clear()
    LOAD_CMDS_TAB.clear()
    EXT_RELOCATIONS.clear()
    USER_CLIENT_METHODS.clear()
    USERSPACE_SERVICES.clear()

    k_header = init_kernel_header(kext_MachO_f)

    # prepare something
    prepare_string(k_header)
    prepare_external_relocations(k_header)
    prepare_loadcmds(k_header)
    prepare_static_vars()

    # collect all meta class
    get_OSMetaClass_initFunc(k_header)

    # check services whether can be open in User-space
    check_effect_service()
    analysis_need_funcs_addr(k_header)

    # analysis inheritance relationship
    analysis_inheritance_base()
    return k_header





def print_help():
    print "Usage:"
    print " python get_openType-bak.py driver_path"
    print " Example: python get_openType-bak.py /Users/lilang_wu/Documents/IOS/ios_fuzz/iokit/xxxdriver-analysis/AppleHDA"

