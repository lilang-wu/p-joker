

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


from capstone import *
from capstone import x86_const


from global_info import *
from arm_regs import x_reg_manager
from extension_analysis import *

def analysis_newUserClient(k_header):
    """
    analysis newUserClient functions and get {openType:UserClient}
    """
    text_vmaddr =   k_header.macho_get_vmaddr("__TEXT", "__text")
    text_fileaddr = k_header.macho_get_fileaddr("__TEXT", "__text")

    for meta_class_addr, meta_class in META_CLASSES.iteritems():
        if meta_class.can_ser_open == 1:
        #if meta_class.can_ser_open == 1 and meta_class.class_name == "AppleHDAEngine":
            if meta_class.newUserClient_vm and meta_class.newUserClient_f:
                #print hex(meta_class.newUserClient_f), hex(meta_class.newUserClient_vm)

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
                        return demangle(uc_name)

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
                    return demangle(uc_name)

            uc_addr = jz_address + 1
            if uc_addr in EXT_RELOCATIONS:
                uc_name = EXT_RELOCATIONS[uc_addr]
            elif uc_addr in STRING_TAB:
                uc_name = STRING_TAB[uc_addr]

            if "UserClient" in uc_name:
                return demangle(uc_name)

        if jz_mnemonic in ["jz", "je"]:
            imm_num = insn.op_count(CS_OP_IMM)
            if imm_num == 1:
                jump_vm = get_single_IMM(insn)
                jump_f = k_header.get_f_from_vm(text_fileaddr, text_vmaddr, int(jump_vm, 16))
                uc_name = analysis_uc_func(k_header, int(jump_vm, 16), jump_f)
                if "UserClient" in uc_name:
                    return demangle(uc_name)

        imm_num = insn.op_count(CS_OP_IMM)
        if imm_num == 1:
            # may be userclient address
            uc_addr = get_single_IMM(insn)
            if uc_addr in EXT_RELOCATIONS:
                uc_name = EXT_RELOCATIONS[uc_addr]
            elif uc_addr in STRING_TAB:
                uc_name = STRING_TAB[uc_addr]
            if "UserClient" in uc_name:
                return demangle(uc_name)


        if jz_mnemonic in ["call", "ret", "jmp"]:
            return ""


def print_openType_results(printall):
    global META_CLASSES

    print "%s" % "-"*50
    print "%3s%10s%10s%18s%40s" % ("index", "CanOpen", "TOpenType", "ServiceName", "extends")
    index = 0
    for meta_class_addr, meta_class in META_CLASSES.iteritems():
        if bool(meta_class.can_ser_open):
            print "%3d%s%-10s%-5s%s%-50s%-50s" % (index, " "*5, bool(meta_class.can_ser_open), meta_class.can_ser_open_type, " "*3, meta_class.class_name, meta_class.extends_list)
        else:
            if printall:
                print "%3d%s%-10s%-5s%s%-50s%-50s" % (index, " "*5, bool(meta_class.can_ser_open), "", " "*3, meta_class.class_name, meta_class.extends_list)
        index += 1

    print
    print "%s" % "-"*50
    print "%-20s%3s%20s" % ("ServiceName", "OpenType", "UserClient")
    for meta_class_addr, meta_class in META_CLASSES.iteritems():
        if meta_class.can_ser_open == 1:
            if meta_class.openType:
                for openType, userclient in meta_class.openType.iteritems():
                    print "%-20s%3s%s%-10s" % (meta_class.class_name, openType, " "*14, userclient)


def get_openType(k_header, printall=True):
    analysis_newUserClient(k_header)
    print_openType_results(printall)



if __name__ == '__main__':
    kext_MachO_f = "/Users/lilang_wu/Documents/IOS/ios_fuzz/iokit/xxxdriver-analysis/Extensions_machO/AppleMCCSControl/AppleMCCSControl"
    kext_MachO_f = "/Users/lilang_wu/Documents/IOS/ios_fuzz/iokit/xxxdriver-analysis/Extensions_machO/AppleHDA/AppleHDA"
    k_header = extension_analysis(kext_MachO_f)
    get_openType(k_header, printall=False)