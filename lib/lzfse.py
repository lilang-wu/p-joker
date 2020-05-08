
import os
import sys
import struct

def get_image_info(filename):
    """Check if it is IMG4 format."""
    if not os.path.isfile(filename):
        print("[e] %s : file not found" % filename)
        sys.exit(-1)

    with open(filename, 'rb') as file:
        for i in range(0x10):
            if ord(file.read(1)) == 0x04:
                break
        magic = file.read(4)
        # print magic
        if magic == b'IM4P':
            magic = "img4"
        else:
            return None
        file.seek(2, os.SEEK_CUR)
        img_type = file.read(4)

        file.seek(2, os.SEEK_CUR)
        version = file.read(18)
        if version == "KernelCacheBuilder":
            subversion = ""
            for i in range(0x1f):
                str = file.read(1)
                if ord(str) >= 0x2D:
                    subversion += str
                else:
                    break
        version += subversion

        file.seek(1, os.SEEK_CUR)

        size = 0
        compress_mode = ""

        size_byte_array = []
        for i in range(0x6):
            size_byte = ord(file.read(1))
            if size_byte == 0x62 or size_byte == 0x63:
                compress_mode = size_byte
                break
            else:
                size_byte_array.append(size_byte)
        array_len = len(size_byte_array)

        for i in range(array_len):
            size += size_byte_array[i] << (4 * (2 * (array_len - 1 - i)))

        if compress_mode == 0x62:
            compress_mode = "bvx2"

        if compress_mode == 0x63:
            compress_mode = "complzss"

    data = None
    data_start = 0
    data_end = 0
    data_size = 0
    kernel_size = 0
    with open(filename, "rb") as kernel:
        kernel.seek(0, 2)
        kernel_size = kernel.tell()

    with open(filename, "rb") as kernel:
        for i in range(0xff):
            tmp_str = kernel.read(3)
            if tmp_str == "bvx":
                data_start = i
                break
            kernel.seek(-2, os.SEEK_CUR)

        kernel.seek(-3, os.SEEK_END)
        for i in range(0xff):
            tmp_str = kernel.read(3)
            # print tmp_str.encode("hex")
            if tmp_str == "bvx":
                data_end = i
                break
            kernel.seek(-4, os.SEEK_CUR)

        data_size = kernel_size - data_start - data_end + 3

        kernel.seek(data_start, os.SEEK_SET)
        data = kernel.read(data_size)
        #print data.encode("hex")


    return magic, img_type, version, size, compress_mode, data