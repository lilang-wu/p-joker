



#get for UserClient->externalMethod()

"""
IOReturn IOUserClient::externalMethod( uint32_t selector, IOExternalMethodArguments * args,
					IOExternalMethodDispatch * dispatch, OSObject * target, void * reference );



Actually, we can do not classify the parser method by the externalMethod or getTarget*, we following the below steps:
    selector1. parser those IOExternalMethodDispatch arrays
    selector2. parser the function asm of externalMethod or getTarget*, and get selector from the cfg...

"""


from extension_analysis import *
from mach_struct import *


def analysis_selector_type1(k_header):
    global USER_CLIENT_METHODS
    global META_CLASSES
    global EXT_RELOCATIONS
    global STRING_TAB

    const_vm        = k_header.macho_get_vmaddr("__TEXT", "__const")
    const_f         = k_header.macho_get_fileaddr("__TEXT", "__const")
    const_size      = k_header.macho_get_size("__TEXT", "__const")
    data_const_vm    = k_header.macho_get_vmaddr("__DATA", "__const")
    data_const_f    = k_header.macho_get_fileaddr("__DATA", "__const")
    data_const_size = k_header.macho_get_size("__DATA", "__const")

    for ucm_vm, ucm in USER_CLIENT_METHODS.iteritems():
        meta_clazz_n  = demangle(ucm).split("::")[0]
        meta_method_n = demangle(ucm).split("(")[0].split("::")[1]
        static_v      = demangle(ucm).split("::")[-1]
        # print meta_clazz_n, meta_method_n

        for meta_class_addr, meta_class in META_CLASSES.iteritems():
            if not cmp(meta_class.class_name, meta_clazz_n):
                start_f = k_header.get_f_from_vm(const_f, const_vm, ucm_vm)

                # setup the check properties
                check_c_vm = const_vm
                check_c_f = const_f
                check_boundary = const_size + const_f

                if start_f >= data_const_f and start_f <= (data_const_size + data_const_f):
                    check_boundary = data_const_size + data_const_f
                    check_c_vm     = data_const_vm
                    check_c_f      = data_const_f

                if is_exclude(static_v, ucm_vm):
                    break

                # print demangle(ucm), hex(ucm_vm)

                # parser different data struct for different method
                if meta_method_n == "externalMethod":
                    meta_class.is_ioemd = True

                    while True:
                        func_addr = k_header.memcpy(start_f, 8)
                        func_name = ""
                        if func_addr in EXT_RELOCATIONS:
                            func_name  = EXT_RELOCATIONS[func_addr]
                        elif func_addr in STRING_TAB:
                            func_name = STRING_TAB[func_addr]
                        if start_f > check_boundary:
                            break

                        if func_name and "::gMetaClass" not in demangle(func_name):
                            io_external_md = IOExternalMethodDispatch()
                            io_external_md.function_addr = func_addr
                            io_external_md.function_name = func_name
                            io_external_md.checkScalarInputCount    = hex(k_header.memcpy(start_f + 8, 4))
                            io_external_md.checkStructureInputSize  = hex(k_header.memcpy(start_f + 12, 4))
                            io_external_md.checkScalarOutputCount   = hex(k_header.memcpy(start_f + 16, 4))
                            io_external_md.checkStructureOutputSize = hex(k_header.memcpy(start_f + 20, 4))
                            meta_class.IOExternalMethodDispatch.append(io_external_md)
                            start_f += 24
                        else:
                            break

                elif meta_method_n == "getTargetAndMethodForIndex":
                    meta_class.is_ioem = True

                    while True:
                        # check the end of IOExternalMethod array
                        # two situations: 1) another metaclass startup; 2) start_f out of const fields.
                        check_addr = k_header.memcpy(start_f, 8)
                        start_vm = k_header.get_vm_from_f(check_c_f, check_c_vm, start_f)
                        if is_end(check_addr, start_vm, ucm):
                            break

                        if start_f >= check_boundary:
                            break

                        # parser the IOExternalMethod array
                        io_external_m = IOExternalMethod()
                        io_external_m.service_object = hex(k_header.memcpy(start_f, 8))
                        IOMethod_addr                = k_header.memcpy(start_f + 8, 8)
                        io_external_m.flags          = hex(k_header.memcpy(start_f + 24, 8))
                        io_external_m.count0         = hex(k_header.memcpy(start_f + 32, 8))
                        io_external_m.count1         = hex(k_header.memcpy(start_f + 40, 8))

                        if IOMethod_addr in EXT_RELOCATIONS:
                            io_external_m.IOMethod = EXT_RELOCATIONS[IOMethod_addr]
                        elif IOMethod_addr in STRING_TAB:
                            io_external_m.IOMethod = STRING_TAB[IOMethod_addr]
                        else:
                            io_external_m.IOMethod = hex(IOMethod_addr)

                        meta_class.IOExternalMethod.append(io_external_m)
                        start_f += 48

                elif meta_method_n == "getAsyncTargetAndMethodForIndex":
                    meta_class.is_ioeam = True

                    while True:
                        # check the end of IOExternalMethod array
                        # two situations: 1) another metaclass startup; 2) start_f out of const fields.
                        check_addr = k_header.memcpy(start_f, 8)
                        start_vm = k_header.get_vm_from_f(check_c_f, check_c_vm, start_f)
                        if is_end(check_addr, start_vm, ucm):
                            break

                        # parser the IOExternalMethod array
                        io_external_am = IOExternalAsyncMethod()
                        io_external_am.service_object = hex(k_header.memcpy(start_f, 8))
                        IOAsyncMethod_addr            = k_header.memcpy(start_f + 8, 8)
                        io_external_am.flags          = hex(k_header.memcpy(start_f + 24, 8))
                        io_external_am.count0         = hex(k_header.memcpy(start_f + 32, 8))
                        io_external_am.count1         = hex(k_header.memcpy(start_f + 40, 8))

                        if IOAsyncMethod_addr in EXT_RELOCATIONS:
                            io_external_am.IOMethod = EXT_RELOCATIONS[IOAsyncMethod_addr]
                        elif IOAsyncMethod_addr in STRING_TAB:
                            io_external_am.IOMethod = STRING_TAB[IOAsyncMethod_addr]
                        else:
                            io_external_am.IOMethod = hex(IOAsyncMethod_addr)

                        meta_class.IOExternalAsyncMethod.append(io_external_am)
                        start_f += 48


def is_exclude(static_v, ucm_vm):
    global SECTION_INDEX
    global LOAD_CMDS_TAB

    if ucm_vm in SECTION_INDEX:
        sec_index = SECTION_INDEX[ucm_vm]
        if LOAD_CMDS_TAB[sec_index] not in ["__TEXT, __const", "__DATA, __const"]:
            return True

    exclude_list = ["os_log_fmt"]
    for ex in exclude_list:
        if ex in static_v:
            return True
    return False


def is_end(check_addr, start_vm, userclient_n):
    global EXT_RELOCATIONS
    global STRING_TAB

    # check the start_vm, the string in these address must be NULL
    check_n = ""
    if start_vm in EXT_RELOCATIONS:
        check_n = EXT_RELOCATIONS[start_vm]
    elif start_vm in STRING_TAB:
        check_n = STRING_TAB[start_vm]
    if check_n and cmp(userclient_n, check_n):
        return True

    # check the content index by the start_vm, if the string index by the content is not NULL, break; else
    if check_addr:
        check_n = ""
        if check_addr in EXT_RELOCATIONS:
            check_n = EXT_RELOCATIONS[check_addr]
        elif check_addr in STRING_TAB:
            check_n = STRING_TAB[check_addr]
        # print check_n, hex(check_addr)
        if check_n:
            return True

        if check_addr:
            return True
    else:
        return False


def print_selector1_results():
    global META_CLASSES
    global USER_CLIENT_METHODS

    for ucm_vm, ucm in USER_CLIENT_METHODS.iteritems():
        meta_clazz_n  = demangle(ucm).split("::")[0]
        meta_method_n = demangle(ucm).split("(")[0].split("::")[1]
        static_v      = demangle(ucm).split("::")[-1]

        if is_exclude(static_v, ucm_vm):
            continue

        for meta_class_addr, meta_class in META_CLASSES.iteritems():
            if not cmp(meta_class.class_name, meta_clazz_n):
                if meta_method_n not in ["externalMethod", "getTargetAndMethodForIndex", "getAsyncTargetAndMethodForIndex"]:
                    continue

                print "%s" % "-" * 150
                print hex(ucm_vm) + " - " + demangle(ucm) + "  confidence: 100%"
                if meta_class.is_ioemd:
                    print "%3s%10s%15s%15s%15s%15s" % ("selector", "cSIC", "cSIS", "cSOC", "cSOS", "func_name")
                    for i in range(len(meta_class.IOExternalMethodDispatch)):
                        ioemd = meta_class.IOExternalMethodDispatch[i]
                        print "%3s%15s%15s%15s%15s%6s%-100s" % (i, ioemd.checkScalarInputCount, ioemd.checkStructureInputSize, ioemd.checkScalarOutputCount, ioemd.checkStructureOutputSize, " ", demangle(ioemd.function_name))

                if meta_class.is_ioem:
                    print "%3s%10s%15s%15s%15s%15s" % ("selector", "flags", "count0", "count1", "service_obj", "func_name")
                    for i in range(len(meta_class.IOExternalMethod)):
                        ioem = meta_class.IOExternalMethod[i]
                        print "%3s%15s%15s%15s%15s%6s%-100s" % (i, ioem.flags, ioem.count0, ioem.count1, ioem.service_object, " ", demangle(ioem.IOMethod))

                if meta_class.is_ioeam:
                    print "%3s%10s%15s%15s%15s%15s" % ("selector", "flags", "count0", "count1", "service_obj", "func_name")
                    for i in range(len(meta_class.IOExternalAsyncMethod)):
                        ioeam = meta_class.IOExternalAsyncMethod[i]
                        print "%3s%15s%15s%15s%15s%6s%-100s" % (i, ioeam.flags, ioeam.count0, ioeam.count1, ioeam.service_object, " ", ioeam.IOAsyncMethod)


def get_type1_selector(k_header):
    analysis_selector_type1(k_header)
    print_selector1_results()


def print_value_sv():
    global LOAD_CMDS_TAB
    global SECTION_INDEX
    global STRING_TAB
    global META_CLASSES

    exclude_list = []
    for meta_addr, meta_class in META_CLASSES.iteritems():
        mc_self = "__ZN%d%s%d%sE" % (len(meta_class.class_name), meta_class.class_name, len("metaClass"), "metaClass")
        mc_super = "__ZN%d%s%d%sE" % (len(meta_class.class_name), meta_class.class_name, len("superClass"), "superClass")
        exclude_list.append(mc_self)
        exclude_list.append(mc_super)

    for k, v in SECTION_INDEX.iteritems():
        if v:
            if LOAD_CMDS_TAB[v] in ["__TEXT, __const", "__DATA, __const"]:
                if not (STRING_TAB[k].startswith("__ZTV") or STRING_TAB[k].startswith("__ZZ")):
                    if STRING_TAB[k] not in exclude_list:
                        print STRING_TAB[k], demangle(STRING_TAB[k]), hex(k)


if __name__ == '__main__':
    #getopenType("/Users/lilang_wu/Documents/IOS/ios_fuzz/iokit/xxxdriver-analysis/AppleHDA")
    #getopenType("/Users/lilang_wu/Documents/IOS/ios_fuzz/iokit/xxxdriver-analysis/IOHDAFamily")
    #getopenType("/Users/lilang_wu/Documents/IOS/ios_fuzz/iokit/xxxdriver-analysis/AppleIntelHD5000Graphics")
    #getopenType("/Users/lilang_wu/Documents/IOS/ios_fuzz/iokit/xxxdriver-analysis/IOGraphicsFamily")
    kext_MachO_f = "/Users/lilang_wu/Documents/IOS/ios_fuzz/iokit/xxxdriver-analysis/IOGraphicsFamily" #IOBluetoothFamily
    k_header = extension_analysis(kext_MachO_f)
    get_type1_selector(k_header)

    #print_value_sv()