import cxxfilt

def type_parser(method_type):
    if method_type.startswith("0x"):
        return method_type
    uc_name = method_type[1:]
    cx_name = cxxfilt.demangle(uc_name)
    if cx_name[-5:] == "const":
        return cx_name[:-6]
    return cx_name


def type_parser1(method_type):
    type_list = list()
    fir_p = -0xff
    cond = True
    for i in range(len(method_type)):
        type_split = dict()
        i_d = method_type[i]
        if i_d.isdigit() and cond:
            fir_p = i
            cond = False
            continue
        if i_d.isdigit() and ((i - fir_p) == 1):
            type_split[i+1] = method_type[fir_p:fir_p+2]
            cond = True
            type_list.append(type_split)
        elif (not i_d.isdigit()) and ((i - fir_p) == 1) and (i_d != "_"):
            type_split[i] = method_type[fir_p:fir_p+1]
            cond = True
            type_list.append(type_split)
        elif (not i_d.isdigit()) and ((i - fir_p) == 1) and (i_d == "_"):
            cond = True

    if not type_list:
        return method_type

    class_dic = type_list[0]
    class_name = method_name = ""
    for k, v in class_dic.iteritems():
        class_name = method_type[k:k + int(v)]
    method_dic = type_list[1]
    for k, v in method_dic.iteritems():
        method_name = method_type[k:k + int(v)]
    args = list()
    if len(type_list) > 2:
        for i in range(2, len(type_list), 1):
            dic = type_list[i]
            for k, v in dic.iteritems():
                args.append(method_type[k:k+int(v)])

    if not class_name or not method_name:
        return method_type

    # print args
    clas_str = "%s::%s(%s)"
    arg_str = ""
    if args:
        for arg in args:
            arg_str = arg_str + ", " + arg
        arg_str = arg_str[2:]
    class_str = clas_str % (class_name, method_name, arg_str)
    return class_str







if __name__ == '__main__':
    print type_parser("__ZNK15IORegistryEntry16getPathComponentEPcPiPK15IORegistryPlane")
    #type_parser("__ZN28IOFilterInterruptEventSource4initEP8OSObjectPFvS1_P22IOInterruptEventSourceiEPFbS1_PS_EP9IOServicei")