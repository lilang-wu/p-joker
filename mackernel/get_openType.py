

"""
get from newUserClient: all we need is to parser the newUserClient, and find the "cmp rcx type"

x64 arguments order: rdi, rsi, rdx, rcx, r8, r9
rax: return value

kern_return_t
IOServiceOpen(
	io_service_t    service,
	task_port_t	owningTask,
	uint32_t	type,
	io_connect_t  *	connect )
{
    kern_return_t	kr;
    kern_return_t	result;

    kr = io_service_open_extended( service,
	owningTask, type, NDR_record, NULL, 0, &result, connect );

    if (KERN_SUCCESS == kr)
        kr = result;

    return (kr);
}

    --call--->

kern_return_t is_io_service_open_extended

    --call--->

IOReturn IOService::newUserClient( task_t owningTask, void * securityID,
                                    UInt32 type,  OSDictionary * properties,
                                    IOUserClient ** handler )

   --call--->

IOReturn IOService::newUserClient( task_t owningTask, void * securityID,
                                    UInt32 type, IOUserClient ** handler )
{
    return( kIOReturnUnsupported );
}


"""
import sys
import struct

sys.path.append("../")

from capstone import *
from capstone import x86_const

from iokit_kextclass.xprint import to_hex, to_x
from iokit_kextclass.OSMetaClass import *
from kernel.offset import MachOHeader

from regs import x_reg_manager
from mach_struct import *
from misc_func import *

from iokitconnection import IOKitConnection


META_CLASSES = {}
STRING_TAB = {}
SYMBOL_TAB = {}
EXT_RELOCATIONS = {}

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

    string_table_f    = k_header.macho_get_fileaddr("__STRINGTAB", "")
    string_table_size = k_header.macho_get_size("__STRINGTAB", "")
    symbol_table_f    = k_header.macho_get_fileaddr("__SYMTAB", "")
    sym_num           = k_header.macho_get_size("__SYMTAB", "")

    offset = symbol_table_f
    for i in range(sym_num):
        index = k_header.memcpy(offset, 4)
        addr = k_header.memcpy(offset + 8, 8)
        string = k_header.get_memStr_from_f(string_table_f + index)
        STRING_TAB[addr] = string
        offset += 16
        SYMBOL_TAB[i] = string


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
    print "Extract: total %d kernel base object modinit" % total_mif

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
                                    meta_class.class_super_name = get_metaclass_name(meta_class.class_super_name)


                            META_CLASSES[meta_class.class_self_addr] = meta_class
                            # print hex(meta_class.metaclass_vt_vm), hex(meta_class.object_vt_vm), meta_class.class_name, meta_class.class_super_name

                            continue

            if mnemonic in ["ret"]:
                break
        #break

def check_effect_service():
    global META_CLASSES

    iokit_instance = IOKitConnection("IOKitServices")
    for meta_class_addr, meta_class in META_CLASSES.iteritems():
        for i in range(100):
            connection = iokit_instance.fuzz_IOServiceOpen(meta_class.class_name, i)
            if not connection:
                meta_class.can_ser_open = 1
                meta_class.can_ser_open_type = i
                break


def analysis_newUserClient(k_header):
    """
    two steps:
        1: find the vm and file offset for every effect class
        2: analysis newUserClient functions and get {openType:UserClient}
    :param k_header:
    :return:
    """

    const_vmaddr =   k_header.macho_get_vmaddr("__TEXT", "__const")
    const_fileaddr = k_header.macho_get_fileaddr("__TEXT", "__const")
    const_size =     k_header.macho_get_size("__TEXT", "__const")


    text_vmaddr =   k_header.macho_get_vmaddr("__TEXT", "__text")
    text_fileaddr = k_header.macho_get_fileaddr("__TEXT", "__text")
    text_size =     k_header.macho_get_size("__TEXT", "__text")

    # find the vm and file addr for every effect class.
    for meta_class_addr, meta_class in META_CLASSES.iteritems():
        if meta_class.can_ser_open == 1:
            newUserClient = "__ZN%d%s%d%s" % (len(meta_class.class_name), meta_class.class_name,
                                              len("newUserClient"), "newUserClient")

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
                    break

                if br_sig == 2:
                    print "Analysis newUserClient: not found newUserClient method, may be implement by its child class"
                    break

                v_func_f += 8
                v_func_vm += 8
                v_func_addr = k_header.memcpy(v_func_f, 8)

    for meta_class_addr, meta_class in META_CLASSES.iteritems():
        if meta_class.can_ser_open == 1:
        #if meta_class.can_ser_open == 1 and meta_class.class_name == "IOFramebuffer":
            if meta_class.newUserClient_vm and meta_class.newUserClient_f:
                # print hex(meta_class.newUserClient_f), hex(meta_class.newUserClient_vm)

                cs_handler = Cs(CS_ARCH_X86, CS_MODE_LITTLE_ENDIAN)
                cs_handler.detail = True  # this is very important
                code = k_header.memcpy(meta_class.newUserClient_f, 0xfff)
                cs_insn = cs_handler.disasm(code, meta_class.newUserClient_vm)
                xr_m = x_reg_manager()

                # all substitutes of arg4: rcx/ecx
                subs_rcx = [x86_const.X86_REG_RCX, x86_const.X86_REG_ECX]
                open_Type = -1
                couple_switch = 0
                for insn in cs_insn:
                    address = insn.address
                    mnemonic = insn.mnemonic
                    op_str = insn.op_str

                    # print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))
                    xr_m.set_actual_value_by_regN(x86_const.X86_REG_RIP, address + insn.size)

                    if mnemonic in ["mov"]:
                        seg_num = insn.op_count(CS_OP_REG)
                        if seg_num == 2:
                            f_reg = get_first_reg(insn)
                            s_reg = get_second_reg(insn)
                            if s_reg in [x86_const.X86_REG_RCX, x86_const.X86_REG_ECX]:
                                subs_rcx.append(f_reg)

                    if mnemonic in ["cmp"]:
                        seg_num = insn.op_count(CS_OP_REG)
                        imm_num = insn.op_count(CS_OP_IMM)
                        if seg_num == 1 and imm_num == 1:
                            f_reg = get_first_reg(insn)
                            if f_reg in subs_rcx:
                                open_Type = get_single_IMM(insn)
                                couple_switch = 1

                    if couple_switch and mnemonic in ["je", "jz"]:
                        imm_num = insn.op_count(CS_OP_IMM)
                        if imm_num == 1:
                            jump_vm = get_single_IMM(insn)
                            jump_f = k_header.get_f_from_vm(text_fileaddr, text_vmaddr, int(jump_vm, 16))
                            userclient = analysis_uc_func(k_header, int(jump_vm, 16), jump_f)
                            print userclient
                            if userclient:
                                meta_class.openType[open_Type] = userclient
                        couple_switch = 0

                    if mnemonic in ["test"]:
                        seg_num = insn.op_count(CS_OP_REG)
                        if seg_num == 2:
                            f_reg = get_first_reg(insn)
                            s_reg = get_second_reg(insn)
                            if f_reg == s_reg and f_reg in subs_rcx:
                                open_Type = 0
                                couple_switch = 1

                    if couple_switch and mnemonic in ["jne", "jnz"]:
                        jump_vm = xr_m.get_actual_value_by_regN(x86_const.X86_REG_RIP)
                        jump_f = k_header.get_f_from_vm(text_fileaddr, text_vmaddr, jump_vm)
                        userclient = analysis_uc_func(k_header, jump_vm, jump_f)
                        print userclient
                        if userclient:
                            meta_class.openType[open_Type] = userclient
                        couple_switch = 0

                    if mnemonic in ["ret"]:
                        break


def analysis_uc_func(k_header, jump_vm, jump_f):
    """
    ugly........

    two situations:
    1): Immediate number in the insn refer to the userclient
    2): the value of registers refer to the userclient
    :param cs_insn:
    :param jump_vm:
    :return:
    """

    global EXT_RELOCATIONS
    global STRING_TAB


    text_vmaddr =   k_header.macho_get_vmaddr("__TEXT", "__text")
    text_fileaddr = k_header.macho_get_fileaddr("__TEXT", "__text")
    text_size =     k_header.macho_get_size("__TEXT", "__text")

    xr_m = x_reg_manager()
    uc_name = ""

    cs_handler = Cs(CS_ARCH_X86, CS_MODE_LITTLE_ENDIAN)
    cs_handler.detail = True  # this is very important
    code = k_header.memcpy(jump_f, 0xff)
    cs_insn = cs_handler.disasm(code, jump_vm)

    for insn in cs_insn:
        jz_address = insn.address
        jz_mnemonic = insn.mnemonic
        jz_op_str = insn.op_str

        # print("0x%x:\t%s\t%s" % (jz_address, jz_mnemonic, jz_op_str))
        xr_m.set_actual_value_by_regN(x86_const.X86_REG_RIP, jz_address + insn.size)

        if jz_mnemonic in ["mov", "lea"]:
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

                    if mem_addr in EXT_RELOCATIONS:
                        uc_name = EXT_RELOCATIONS[mem_addr]
                    elif mem_addr in STRING_TAB:
                        uc_name = STRING_TAB[mem_addr]
                    if "UserClient" in uc_name:
                        return __clear_uc_name(uc_name)

        if jz_mnemonic in ["call"]:
            imm_num = insn.op_count(CS_OP_IMM)
            if imm_num == 1:
                imm = get_single_IMM(insn)
                uc_addr = int(imm, 16)
                if uc_addr in EXT_RELOCATIONS:
                    uc_name = EXT_RELOCATIONS[uc_addr]
                elif uc_addr in STRING_TAB:
                    uc_name = STRING_TAB[uc_addr]

                if "UserClient" in uc_name:
                    return __clear_uc_name(uc_name)

            uc_addr = jz_address + 1
            if uc_addr in EXT_RELOCATIONS:
                uc_name = EXT_RELOCATIONS[uc_addr]
            elif uc_addr in STRING_TAB:
                uc_name = STRING_TAB[uc_addr]

            if "UserClient" in uc_name:
                return __clear_uc_name(uc_name)

        if jz_mnemonic in ["jz", "je"]:
            imm_num = insn.op_count(CS_OP_IMM)
            if imm_num == 1:
                jump_vm = get_single_IMM(insn)
                jump_f = k_header.get_f_from_vm(text_fileaddr, text_vmaddr, int(jump_vm, 16))
                uc_name = analysis_uc_func(k_header, int(jump_vm, 16), jump_f)
                if "UserClient" in uc_name:
                    return __clear_uc_name(uc_name)

        imm_num = insn.op_count(CS_OP_IMM)
        if imm_num == 1:
            # may be userclient address
            uc_addr = get_single_IMM(insn)
            if uc_addr in EXT_RELOCATIONS:
                uc_name = EXT_RELOCATIONS[uc_addr]
            elif uc_addr in STRING_TAB:
                uc_name = STRING_TAB[uc_addr]
            if "UserClient" in uc_name:
                return __clear_uc_name(uc_name)


        if jz_mnemonic in ["call", "ret", "jmp"]:
            return ""


def __clear_uc_name(uc_name):
    if uc_name.startswith("__ZN"):
        return get_metaclass_name(uc_name)
    elif uc_name.startswith("__ZTV"):
        return get_metaclass_name(uc_name, prefix="__ZTV")
    else:
        return uc_name


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
                super_addr = META_CLASSES[super_addr].class_super_addr
            elif super_addr in EXT_RELOCATIONS:
                extends_rela = __clear_uc_name(EXT_RELOCATIONS[super_addr]) + extends_rela
                extends_rela = "-->" + extends_rela
                meta_class.class_super_list.append(super_addr)
                break

        if "-->" in extends_rela:
            extends_rela = extends_rela[3:]
            extends_rela = extends_rela + "-->" +  meta_class.class_name

        meta_class.extends_list = extends_rela


def print_results():
    analysis_inheritance_base()
    global META_CLASSES

    print "%s" % "-"*50
    print "%3s%10s%10s%18s%40s" % ("index", "CanOpen", "TOpenType", "ServiceName", "extends")
    index = 0
    for meta_class_addr, meta_class in META_CLASSES.iteritems():
        if bool(meta_class.can_ser_open):
            print "%3d%s%-10s%-5s%s%-50s%-50s" % (index, " "*5, bool(meta_class.can_ser_open), meta_class.can_ser_open_type, " "*3, meta_class.class_name, meta_class.extends_list)
        else:
            print "%3d%s%-10s%-5s%s%-50s" % (index, " "*5, bool(meta_class.can_ser_open), "", " "*3, meta_class.class_name)
        index += 1

    print
    print "%s" % "-"*50
    print "%-20s%3s%20s" % ("ServiceName", "OpenType", "UserClient")
    for meta_class_addr, meta_class in META_CLASSES.iteritems():
        if meta_class.can_ser_open == 1:
            if meta_class.openType:
                for openType, userclient in meta_class.openType.iteritems():
                    print "%-20s%3s%s%-10s" % (meta_class.class_name, openType, " "*14, userclient)



def getopenType(kext_MachO_f):
    k_header = init_kernel_header(kext_MachO_f)

    # prepare something
    prepare_string(k_header)
    prepare_external_relocations(k_header)

    # collect all meta class
    get_OSMetaClass_initFunc(k_header)
    #"""
    # check services whether can be open in User-space
    check_effect_service()

    # analysis extent relationship and check its newUserClient function
    analysis_newUserClient(k_header)

    # print the last results
    print_results()
    #"""


if __name__ == '__main__':
    getopenType("/Users/lilang_wu/Documents/IOS/ios_fuzz/iokit/xxxdriver-analysis/AppleHDA")
    #getopenType("/Users/lilang_wu/Documents/IOS/ios_fuzz/iokit/xxxdriver-analysis/IOHDAFamily")
    #getopenType("/Users/lilang_wu/Documents/IOS/ios_fuzz/iokit/xxxdriver-analysis/AppleIntelHD5000Graphics")
    #getopenType("/Users/lilang_wu/Documents/IOS/ios_fuzz/iokit/xxxdriver-analysis/IOGraphicsFamily")