
import cxxfilt

def demangle(uc_name):
    if uc_name.startswith("0x"):
        return uc_name
    uc_name = uc_name[1:]
    return cxxfilt.demangle(uc_name)

if __name__ == '__main__':

    print demangle("0x961")