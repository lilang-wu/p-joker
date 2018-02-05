
import os


kext_10_file                 = "kernel_10_3_2_kext.txt"
syscalls_10_file             = "kernel_10_3_2_syscalls.txt"
sysctls_10_file              = "kernel_10_3_2_sysctls.txt"
trap_10_file                 = "kernel_10_3_2_trap.txt"
system_library_10            = "10_3_2_System_Library.txt"
system_library_frameworks_10 = "10_3_2_System_Library_Frameworks.txt"
usr_libexec_10               = "10_3_2_usr_libexec.txt"
usr_sbin_10                  = "10_3_2_usr_sbin.txt"
system_library_privatefw_10  = "10_3_2_System_Library_PrivateFrames.txt"

kext_11_file                 = "kernel_11_beta2_kext.txt"
syscalls_11_file             = "kernel_11_beta2_syscalls.txt"
sysctls_11_file              = "kernel_11_beta2_sysctls.txt"
trap_11_file                 = "kernel_11_beta2_trap.txt"
system_library_11            = "11_System_Library.txt"
system_library_frameworks_11 = "11_System_Library_Frameworks.txt"
usr_libexec_11               = "11_usr_libexec.txt"
usr_sbin_11                  = "11_usr_sbin.txt"
system_library_privatefw_11  = "11_System_Library_PrivateFrameworks.txt"



ios10_path = "/home/wdy/ipsw/iphone7/iPhone_7_10_3_2"
ios11_path = "/home/wdy/ipsw/iphone7/iPhone_7_11"

cmp_dir = "/home/wdy/ipsw/iphone7/cmp"


def read_file(file_name, start=0, step=1):
    content = []
    with file(file_name, 'r') as f:
        lines = f.readlines()
        for i in range(start, len(lines), step):
            content.append(lines[i])
    f.close()
    return content

def __save_file(output_dir, filename, info_list=[]):
    tmp_path = output_dir + os.sep + filename
    try:
        with file(tmp_path, 'w') as f:
            for info in info_list:
                f.write(info.strip())
                f.write("\n")
        f.close()
        return True
    except Exception, e:
        return False


def diff_system(orign={}, now={}):
    same = []
    diff_10 = []
    diff_11 = []
    for sc in orign.keys():
        if sc in now:
            same.append(sc)
        else:
            diff_10.append(sc)

    for sc in now.keys():
        if sc not in same:
            diff_11.append(sc)
    return same, diff_10, diff_11

def diff_system_list(orign=[], now=[]):
    same = []
    diff_10 = []
    diff_11 = []
    for sc in orign:
        if sc in now:
            same.append(sc)
        else:
            diff_10.append(sc)

    for sc in now:
        if sc not in same:
            diff_11.append(sc)
    return same, diff_10, diff_11

def get_kexts(kexts):
    s_kext = {}
    for kext in kexts:
        kext_list = kext.split(":")
        s_kext[kext_list[1].strip()] = kext_list[0].strip()
    return s_kext

def get_syscalls(syscalls):
    # have two syscall: proc_rlimit_control
    scall = {}
    for syscall in syscalls:
        sc = syscall.split(" ")
        id = sc[0].strip()
        call = sc[1].strip()
        addr = sc[-1].strip()
        scall[call] = addr
    return scall

def get_sysctls(sysctls):
    sctls = {}
    for ctl in sysctls:
        ctls = ctl.split(" ")
        addr = ctls[0].strip(":")
        name = ctls[1].split("\t")[0].strip()
        sctls[name] = addr
    return sctls

def get_traps(traps):
    m_trap = {}
    for trap in traps:
        if "@" in trap:
            continue
        if ":" in trap:
            continue
        trap_list = trap.split(" ")
        # print trap_list
        if trap_list[0] != "":
            name = trap_list[1].strip()
        else:
            name = trap_list[2].strip()
        addr = trap_list[-2].strip()
        m_trap[name] = addr
    return m_trap

def get_migs(migs):
    m_migs = {}
    for mig in migs:
        if "@" in mig:
            continue
        if ":" not in mig:
            continue
        mig_list = mig.split(":")
        name = mig_list[0].split("\t")[1].replace("__X", "").strip()
        addr = mig_list[1].split("(")[0].strip()
        # print name, addr
        m_migs[name] = addr
    return m_migs



def save_result(dir, name, same, diff_old, diff_new):
    __save_file(dir, "kernel_same_" + name + ".txt", same)
    __save_file(dir, "kernel_diff_old_" + name + ".txt", diff_old)
    __save_file(dir, "kernel_diff_new_" + name + ".txt", diff_new)



if __name__ == '__main__':
    """
    # diff kext
    kexts = read_file(ios10_path + os.sep + kext_10_file, 2, 1)
    kexts_10 = get_kexts(kexts)

    kexts = read_file(ios11_path + os.sep + kext_11_file, 2, 1)
    kexts_11 = get_kexts(kexts)
    same, diff_10, diff_11 = diff_system(kexts_10, kexts_11)
    save_result(cmp_dir, "kexts", same, diff_10, diff_11)

    # diff syscalls
    syscalls = read_file(ios10_path + os.sep + syscalls_10_file, 5, 1)
    scall_10 = get_syscalls(syscalls)
    syscalls = read_file(ios11_path + os.sep + syscalls_11_file, 5, 1)
    scall_11 = get_syscalls(syscalls)
    same, diff_10, diff_11 = diff_system(scall_10, scall_11)
    save_result(cmp_dir, "syscalls", same, diff_10, diff_11)

    # diff sysctls
    sysctls = read_file(ios10_path + os.sep + sysctls_10_file, 3, 6)
    sysctls_10 = get_sysctls(sysctls)
    sysctls = read_file(ios11_path + os.sep + sysctls_11_file, 3, 6)
    sysctls_11 = get_sysctls(sysctls)
    same, diff_10, diff_11 = diff_system(sysctls_10, sysctls_11)
    save_result(cmp_dir, "sysctls", same, diff_10, diff_11)

    # diff traps and migs
    traps = read_file(ios10_path + os.sep + trap_10_file, 4, 1)
    traps_10 = get_traps(traps)
    migs_10 = get_migs(traps)

    traps = read_file(ios11_path + os.sep + trap_11_file, 4, 1)
    traps_11 = get_traps(traps)
    migs_11 = get_migs(traps)

    same, diff_10, diff_11 = diff_system(traps_10, traps_11)
    save_result(cmp_dir, "traps", same, diff_10, diff_11)

    same, diff_10, diff_11 = diff_system(migs_10, migs_11)
    save_result(cmp_dir, "migs", same, diff_10, diff_11)
    """

    s_library_10 = read_file(ios10_path + os.sep + system_library_10)
    s_library_11 = read_file(ios11_path + os.sep + system_library_11)
    same, diff_10, diff_11 = diff_system_list(s_library_10, s_library_11)
    #save_result(cmp_dir, "system_library", same, diff_10, diff_11)

    sl_frameworks_10 = read_file(ios10_path + os.sep + system_library_frameworks_10, 0, 1)
    sl_frameworks_11 = read_file(ios11_path + os.sep + system_library_frameworks_11, 0, 1)
    same, diff_10, diff_11 = diff_system_list(sl_frameworks_10, sl_frameworks_11)
    #save_result(cmp_dir, "system_library_frameworks", same, diff_10, diff_11)

    u_libexec_10 = read_file(ios10_path + os.sep + usr_libexec_10, 0, 1)
    u_libexec_11 = read_file(ios11_path + os.sep + usr_libexec_11, 0, 1)
    same, diff_10, diff_11 = diff_system_list(u_libexec_10, u_libexec_11)
    #save_result(cmp_dir, "ulibexec", same, diff_10, diff_11)

    u_sbin_10 = read_file(ios10_path + os.sep + usr_sbin_10, 0, 1)
    u_sbin_11 = read_file(ios11_path + os.sep + usr_sbin_11, 0, 1)
    same, diff_10, diff_11 = diff_system_list(u_sbin_10, u_sbin_11)
    #save_result(cmp_dir, "usbin", same, diff_10, diff_11)


    sl_pf_10 = read_file(ios10_path + os.sep + system_library_privatefw_10, 0, 1)
    sl_pf_11 = read_file(ios11_path + os.sep + system_library_privatefw_11, 0, 1)
    same, diff_10, diff_11 = diff_system_list(sl_pf_10, sl_pf_11)
    save_result(cmp_dir, "privateframeworks", same, diff_10, diff_11)

    #print len(sysctls_10), len(sysctls_11)




