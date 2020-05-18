

IOS_VERSION_10 = 10
IOS_VERSION_11 = 11
IOS_VERSION_12 = 12
IOS_VERSION_13 = 13

KERNELCACHE_OLD = 20
KERNELCACHE_NEW = 21

A11 = "T8015"  # for iPhone 8, iPhone 8 Plus and iPhone X
A12 = "T8020"  # for iPad Air (3rd generation), iPad mini (5th generation), iPhone XR, iPhone XS and iPhone XS Max
A13 = "T8030"  # for iPhone 11, iPhone 11 Pro, iPhone 11 Pro Max and iPhone SE (2nd generation)
A14 = ""  # can support later
UNKONW = None


class OSInfo(object):
    os_version = 0
    format = 0
    processor = 0


def set_system_version(text_const, kernel_handler):
    global os_version
    if "xnu-3789" in text_const:
        OSInfo.os_version = IOS_VERSION_10
    elif "xnu-4903" in text_const:
        OSInfo.os_version = IOS_VERSION_12
    elif "xnu-6153" in text_const:
        OSInfo.os_version = IOS_VERSION_13

    if "__PRELINK_INFO,__kmod_start" in kernel_handler.get_section_addrs():
        OSInfo.format = KERNELCACHE_NEW
    else:
        OSInfo.format = KERNELCACHE_OLD

    if A11 in text_const:
        OSInfo.processor = A11
    elif A12 in text_const:
        OSInfo.processor = A12
    elif A13 in text_const:
        OSInfo.processor = A13
    else:
        OSInfo.processor = UNKONW


class KernelCacheInfo(object):
    prelink_text_start_vm = 0
    prelink_text_end_vm = 0

    plk_text_start_vm = 0
    plk_text_end_vm = 0

    pdc_data_start_vm = 0
    pdc_data_end_vm = 0

    pd_data_start_vm = 0
    pd_data_end_vm = 0

    prelink_info_start_vm = 0
    prelink_info_end_vm = 0


def is_located_in_prelink_sections(vm_addr):
    if KernelCacheInfo.prelink_text_start_vm < vm_addr < KernelCacheInfo.prelink_text_end_vm:
        return True

    if KernelCacheInfo.plk_text_start_vm < vm_addr < KernelCacheInfo.plk_text_end_vm:
        return True

    if KernelCacheInfo.pdc_data_start_vm < vm_addr < KernelCacheInfo.pdc_data_end_vm:
        return True

    if KernelCacheInfo.pd_data_start_vm < vm_addr < KernelCacheInfo.pd_data_end_vm:
        return True

    if KernelCacheInfo.prelink_info_start_vm < vm_addr < KernelCacheInfo.prelink_info_end_vm:
        return True
    return False