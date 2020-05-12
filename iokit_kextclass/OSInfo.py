

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
