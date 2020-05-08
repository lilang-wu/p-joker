
import os
import sys
import getopt

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


def analysis_extensions_v5(driver_p): # only get meta class names of all drivers
    """
    only get all the meta classes' name for one driver
    :param root_dir:
    :return:
    """
    k_header = extension_analysis(driver_p)
    global META_CLASSES
    for meta_class_addr, meta_class in META_CLASSES.iteritems():
        print meta_class.class_name


def Usage():
    print " Usage: python p-extensions.py -mpfc extension_path/extension_macho"
    print "\t -h, --help"
    print "\t -C, --classes: get all the metaclass for all extensions' macho file in the given extension_path"
    print "\t -c, --class: get all the metaclass for one extension macho"
    print "\t -m, --macho: only analyze one kernel extension macho"
    print "\t -M, --machoes: analyze all kernel extensions' macho file in the given extension_path"


if __name__ == '__main__':
    if len(sys.argv) < 2:
        Usage()
        exit(0)

    try:
        options, args = getopt.getopt(sys.argv[1:], "hC:c:m:M:", ["help", "classes=", "class=", "macho=", "machoes="])
    except getopt.GetoptError:
        exit(0)

    if not len(options):
        Usage()
        exit(0)

    for name, value in options:
        if name in ("-h", "--help"):
            Usage()
            exit(0)
        elif name in ("-m", "--macho"):
            target_f = value
            analysis_extensions_v3(target_f)

        elif name in ("-M", "--machoes"):
            target_p = value
            analysis_extensions_v2(target_p)

        elif name in ("-C", "--classes"):
            target_p = value
            analysis_extensions_v4(target_p)

        elif name in ("-c", "--class"):
            target_f = value
            analysis_extensions_v5(target_f)

        else:
            exit(0)
