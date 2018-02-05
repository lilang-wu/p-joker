

import sys
sys.path.append("../")
from kernel.offset import MachOHeader


prelink_kext_vm = -1
prelink_kext_f = -1
prelink_kext_size = -1

got_info = dict()


def prepare_offset(k_header):
    global prelink_kext_vm
    global prelink_kext_f
    global prelink_kext_size

    prelink_kext_vm   = k_header.macho_get_vmaddr("__PRELINK_TEXT", "")
    prelink_kext_f    = k_header.macho_get_fileaddr("__PRELINK_TEXT", "")
    prelink_kext_size = k_header.macho_get_size("__PRELINK_TEXT", "")


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


def analysis_mif(k_header=None):
    global got_info
    got_start = k_header.macho_get_vmaddr("__DATA_CONST", "__got")
    got_size = k_header.macho_get_size("__DATA_CONST", "__got")
    got_end = got_start + got_size
    got_info[got_start] = got_end


def get_section_addr(kernel_header, kernel_f):
    global prelink_kext_vm
    global prelink_kext_f

    driver_list_p, driver_list_np = kernel_header.get_driver_list()
    prelink_f_offset = prelink_kext_vm - prelink_kext_f
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

        analysis_mif(kext_header)


def getSubIOServicesClass(kernel_f):
    k_header = init_kernel_header(kernel_f)
    prepare_offset(k_header)
    get_section_addr(k_header, kernel_f)


if __name__ == '__main__':
    getSubIOServicesClass("/home/wdy/ipsw/iphonex/11_2_2/kernel_x")
    import json
    with open('/home/wdy/ipsw/ipsw-tools/iokit_kextclass/got_info.txt', 'w') as outfile:
        json.dump(got_info, outfile)