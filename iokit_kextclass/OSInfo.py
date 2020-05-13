

IOS_VERSION_10 = 10
IOS_VERSION_11 = 11
IOS_VERSION_12 = 12
IOS_VERSION_13 = 13

class OSInfo(object):
    os_version = 0


def set_system_version(version_str):
    global os_version
    if "xnu-3789" in version_str:
        OSInfo.os_version = IOS_VERSION_10
    elif "xnu-4903" in version_str:
        OSInfo.os_version = IOS_VERSION_12
    elif "xnu-6153" in version_str:
        OSInfo.os_version = IOS_VERSION_13


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