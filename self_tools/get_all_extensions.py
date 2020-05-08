
import sys
import os
import shutil
import binascii

def get_extensions(src_path="/Users/zuff/Documents/work_dir/iokit_fuzz/Extensions", ext_dir="/Users/zuff/Documents/work_dir/iokit_fuzz/Extensions_machO"):
    """
    copy all the extensions files into ext_dir directory.
    :param src_path:
    :param ext_dir:
    :return:
    """
    for f_dir in os.listdir(src_path):
        driver_n = f_dir.split(".")[0]
        dn_suffix = f_dir.split(".")[-1]
        if dn_suffix == "dSYM":
            continue

        if dn_suffix != "kext":
            continue

        driver_p = src_path + os.sep + f_dir

        # creat a dir which can store these drivers
        dis_path = ext_dir + os.sep + driver_n
        if not os.path.exists(dis_path):
            os.mkdir(dis_path)
        else:
            continue

        # get the path of driver macho path
        for par, dir_list, f_list in os.walk(driver_p):
            for f in f_list:
                if not cmp(f, driver_n):
                    mach_path = os.path.join(par, f)
                    shutil.copy(mach_path, dis_path)
    print "finished!, good luck to you!"


def get_all_extensions_machO(src_path="/System/Library/Extensions", ext_dir="/Users/lilang_wu/Documents/vulnerabilities/macOS/p-joker/Extensions_machO"):
    """
    copy all extensions' macho file into ext_dir directory
    :param src_path:
    :param ext_dir:
    :return:
    """
    for f_dir in os.listdir(src_path):
        driver_n = f_dir.split(".")[0]
        dn_suffix = f_dir.split(".")[-1]
        if dn_suffix == "dSYM":
            continue

        if dn_suffix != "kext":
            continue

        driver_p = src_path + os.sep + f_dir

        # creat a dir which can store these drivers
        if not os.path.exists(ext_dir):
            os.mkdir(ext_dir)

        dis_path = ext_dir + os.sep + driver_n
        if not os.path.exists(dis_path):
            os.mkdir(dis_path)

        # get the path of driver macho path
        for par, dir_list, f_list in os.walk(driver_p):
            for f in f_list:
                mach_file_p = par + os.sep + f
                if get_type(mach_file_p) == "macho":
                    shutil.copy(mach_file_p, dis_path)

    print "finished!, good luck to you!"


def get_type(path):
    """
    check whether the file is macho file
    :param path:
    :return:
    """
    # macho
    f = open(path, "rb")
    data = f.read(5)
    f.close()
    # print binascii.b2a_hex(data) #cffaedfe07
    if (len(data) == 5) and (binascii.b2a_hex(data[0])[0] == "c") and (data[1:5] == "\xfa\xed\xfe\x07"):
        return "macho"

    #
    f = open(path, "rb")
    data = f.read(12)
    f.close()

    # print binascii.b2a_hex(data)
    if (len(data) == 12) and (data[0:7] == "\xCA\xFE\xBA\xBE\x00\x00\x00") and (
        binascii.b2a_hex(data[7])[0] == "0") and (data[8:12] == "\x00\x00\x00\x0C"):
        return "macho"

    return ""


def get_extension_index(driver_n="IOGraphicsFamily", ext_dir="/Users/lilang_wu/Documents/IOS/ios_fuzz/iokit/xxxdriver-analysis/Extensions_machO"):
    """
    get the extension index in order to excluded them if error occurs
    :param driver_n:
    :param ext_dir:
    :return:
    """
    index = 0
    for f_dir in os.listdir(ext_dir):
        if "DS_Store" in f_dir:
            continue
        print str(index) + "\t" + f_dir
        """
        if not cmp(f_dir, driver_n):
            print index
            break

        """
        index += 1

if __name__ == '__main__':
    #get_extensions()
    #get_extension_index()
    print get_type("/System/Library/Extensions/AMDRadeonX4000.kext/Contents/MacOS/AMDRadeonX4000")
    get_all_extensions_machO()