
import os
import sys

sys.path.append("../")
from mackernel.extension_analysis import *
from mackernel.service_get_openType import *
from mackernel.service_get_selector_type1 import *
from mackernel.global_info import *

analysis_root_path = "/Users/lilang_wu/Documents/vulnerabilities/macOS/p-joker/Extensions_machO"


def analysis_extensions_v1(root_dir=analysis_root_path):
    """
    enumerate the external methods and connection types for all Service classes in the given path
    :param root_dir:
    :return:
    """
    dirs = os.listdir(root_dir)
    print len(dirs)
    #index = 0
    for i in range(0, len(dirs)):

        dri_dir = dirs[i]
        if dri_dir.startswith("."):
            continue

        driver_p = root_dir + os.sep + dri_dir + os.sep + dri_dir
        #print str(i) + "\t" + dri_dir + "\t" + "*" * 50
        print str(i) + "*" * 120
        print dri_dir, driver_p
        if i in [106, ]: #56, 96, 103, 107, 124, 125, 126, 128, 129, 131, 150, 164]:
            continue
        if not os.path.exists(driver_p):
            continue

        global USERSPACE_SERVICES

        k_header = extension_analysis(driver_p)
        if USERSPACE_SERVICES["opened"] != 0:
            # print str(i) + "\t" + dri_dir + "\t" + "*" * 50
            get_openType(k_header)
            get_type1_selector(k_header)
            print
            print
            print
        #index += 1
        #break


def analysis_extensions_v2(root_dir=analysis_root_path):
    """
    analysis all extensions in the root_dir path
    """
    dirs = os.listdir(root_dir)
    print len(dirs)
    index = 0
    for i in range(0, len(dirs)):

        dri_dir = dirs[i]
        if dri_dir.startswith("."):
            continue

        driver_p = root_dir + os.sep + dri_dir + os.sep + dri_dir
        if i in [106, ]: #56, 96, 103, 107, 124, 125, 126, 128, 129, 131, 150, 164]:
            continue
        if not os.path.exists(driver_p):
            continue

        global USERSPACE_SERVICES

        k_header = extension_analysis(driver_p)
        if USERSPACE_SERVICES["opened"] != 0:
            print str(index) + "*" * 120
            print dri_dir, driver_p
            get_openType(k_header)
            get_type1_selector(k_header)
            print
            print
            print
            index += 1
        #break


def analysis_extensions_v3(driver_path):
    """
    only analysis one macho
    """
    k_header = extension_analysis(driver_path)
    #if USERSPACE_SERVICES["opened"] != 0:
    print "*" * 120
    get_openType(k_header)
    get_type1_selector(k_header)
    print
    print
    print


def analysis_extensions_v4(root_dir=analysis_root_path): # only get meta class names of all drivers
    """
    only get all the meta classes' name for all the drivers
    :param root_dir:
    :return:
    """
    dirs = os.listdir(root_dir)
    print len(dirs)
    index = 0
    for i in range(0, len(dirs)):

        dri_dir = dirs[i]
        if dri_dir.startswith("."):
            continue

        driver_p = root_dir + os.sep + dri_dir + os.sep + dri_dir
        if i in [106, ]: #56, 96, 103, 107, 124, 125, 126, 128, 129, 131, 150, 164]:
            continue
        if not os.path.exists(driver_p):
            continue

        global USERSPACE_SERVICES

        k_header = extension_analysis(driver_p)
        #if USERSPACE_SERVICES["opened"] != 0:
        global META_CLASSES
        for meta_class_addr, meta_class in META_CLASSES.iteritems():
            print meta_class.class_name
        index += 1
        #break




if __name__ == '__main__':
    #analysis_extensions_v1()
    analysis_extensions_v2()
    #analysis_extensions_v3("/Users/lilang_wu/Documents/vulnerabilities/macOS/p-joker/Extensions_machO/AMDRadeonX4000/AMDRadeonX4000")
    #analysis_extensions_v4()

    #analysis_extensions_v3("/Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/AppleGraphicsControl.kext/Contents/PlugIns/AppleMuxControl.kext/Contents/MacOS/AppleMuxControl")
    #/Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/AppleHDA.kext/Contents/PlugIns/AppleMikeyDriver.kext/Contents/MacOS/AppleMikeyDriver
    #
    #USB:
    #1./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBFamily.kext/Contents/PlugIns/AppleLegacyUSBAudio.kext/Contents/MacOS/AppleLegacyUSBAudio
    #2./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBFamily.kext/Contents/PlugIns/AppleUSBLegacyHub.kext/Contents/MacOS/AppleUSBLegacyHub
    #3./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBFamily.kext/Contents/PlugIns/AppleUSBMergeNub.kext/Contents/MacOS/AppleUSBMergeNub
    #4./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBFamily.kext/Contents/PlugIns/IOUSBCompositeDriver.kext/Contents/MacOS/IOUSBCompositeDriver
    #5./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBFamily.kext/Contents/PlugIns/IOUSBHIDDriver.kext/Contents/MacOS/IOUSBHIDDriver
    #6./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBFamily.kext/Contents/PlugIns/IOUSBHIDDriverPM.kext/Contents/MacOS/IOUSBHIDDriverPM
    #7./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBFamily.kext/Contents/PlugIns/IOUSBUserClient.kext/Contents/MacOS/IOUSBUserClient
    #
    #IOUSBHostFamily
    #1./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/MacOS/IOUSBHostFamily
    #2./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/PlugIns/IOUSBHostHIDDevice.kext/Contents/MacOS/IOUSBHostHIDDevice
    #3./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/PlugIns/AppleUSBXHCIPCI.kext/Contents/MacOS/AppleUSBXHCIPCI
    #4./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/PlugIns/AppleUSBXHCI.kext/Contents/MacOS/AppleUSBXHCI
    #5./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/PlugIns/AppleUSBVHCI.kext/Contents/MacOS/AppleUSBVHCI
    #6./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/PlugIns/AppleUSBUHCIPCI.kext/Contents/MacOS/AppleUSBUHCIPCI
    #7./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/PlugIns/AppleUSBUHCI.kext/Contents/MacOS/AppleUSBUHCI
    #8./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/PlugIns/AppleUSBOpticalMouse.kext/Contents/MacOS/AppleUSBOpticalMouse
    #9./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/PlugIns/AppleUSBHub.kext/Contents/MacOS/AppleUSBHub
    #10./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/PlugIns/AppleUSBHostPacketFilter.kext/Contents/MacOS/AppleUSBHostPacketFilter
    #11./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/PlugIns/AppleUSBHostMergeProperties.kext/Contents/MacOS/AppleUSBHostMergeProperties
    #12./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/PlugIns/AppleUSBHostCompositeDevice.kext/Contents/MacOS/AppleUSBHostCompositeDevice
    #13./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/PlugIns/AppleUSBHostBillboardDevice.kext/Contents/MacOS/AppleUSBHostBillboardDevice
    #14./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/PlugIns/AppleUSBEHCIPCI.kext/Contents/MacOS/AppleUSBEHCIPCI
    #15./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/IOUSBHostFamily.kext/Contents/PlugIns/AppleUSBEHCI.kext/Contents/MacOS/AppleUSBEHCI
    #
    #AppleGraphicsControl
    #1./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/AppleGraphicsControl.kext/Contents/PlugIns/AppleGraphicsDeviceControl.kext/AppleGraphicsDeviceControl
    #2./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/AppleGraphicsControl.kext/Contents/PlugIns/AppleGPUWrangler.kext/Contents/MacOS/AppleGPUWrangler
    #3./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/AMD7000Controller.kext/Contents/MacOS/AMD7000Controller
    #4./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/AppleGraphicsControl.kext/Contents/PlugIns/AppleGraphicsDevicePolicy.kext/Contents/MacOS/AppleGraphicsDevicePolicy
    #5./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/AppleGraphicsControl.kext/Contents/PlugIns/AGDCBacklightControl.kext/Contents/MacOS/AGDCBacklightControl
    #6./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/AppleGraphicsControl.kext/Contents/PlugIns/ApplePolicyControl.kext/Contents/MacOS/ApplePolicyControl
    #7./Users/zuff/Documents/work_dir/iokit_fuzz/Extensions/AppleGraphicsControl.kext/Contents/PlugIns/AppleMuxControl.kext/Contents/MacOS/AppleMuxControl