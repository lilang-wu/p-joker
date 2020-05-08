import os
import sys
import struct
sys.path.append("../")
from lib.mach_o import *
from lib.util import fileview
import xml.etree.ElementTree as ET

class MachOHeader(object):

    def __init__(self, fh, offset, size):
        self.MH_MAGIC = MH_MAGIC_64
        self.mach_header = mach_header_64
        self.endian = '<'

        self.offset = offset
        self.size = size
        self.prelink_offset = 0
        self.kernel_header = None
        self.fh = fileview(fh, offset, size)

    def get_driver_list(self):
        driver_list_prelink = {}
        driver_list_notprelink = []

        sec_addr = self.macho_get_fileaddr("__PRELINK_INFO", "__info")
        sec_size = self.macho_get_size("__PRELINK_INFO", "__info")

        section = self.memcpy(sec_addr, sec_size)
        tree = ET.fromstring(section.strip("\x00"))
        for bundle in tree.iterfind("array/dict"):
            driver_dict = {}
            driver_details = self.__parser_driver_dict(ET.tostring(bundle))
            if "_PrelinkExecutableLoadAddr" in driver_details:
                if "Pseudoextension" in driver_details["CFBundleName"]:
                    driver_list_notprelink.append(driver_details["CFBundleIdentifier"])
                else:
                    driver_list_prelink[driver_details["CFBundleIdentifier"]] = driver_details["_PrelinkExecutableLoadAddr"]
            else:
                driver_list_notprelink.append(driver_details["CFBundleIdentifier"])
        return driver_list_prelink, driver_list_notprelink

    def __parser_driver_dict(self, bundle):
        attr_dict = {}
        tree = ET.fromstring(bundle)
        iskey = True
        key = ""
        for child in tree:
            if iskey:
                key = child.text
                iskey = False
            else:
                attr_dict[key] = child.text
                iskey = True
        return attr_dict

    def macho_get_vmaddr(self, segname, sectname):
        fh = self.fh
        fh.seek(0)

        self.sizediff = 0
        kw = {'_endian_': self.endian}
        header = self.mach_header.from_fileobj(fh, **kw)

        read_bytes = 0
        low_offset = sys.maxsize
        for i in range(header.ncmds):
            # read the load command
            cmd_load = load_command.from_fileobj(fh, **kw)
            # read the specific command
            klass = LC_REGISTRY.get(cmd_load.cmd, None)

            if klass is None:
                raise ValueError("Unknown load command: %d" % (cmd_load.cmd,))
            cmd_cmd = klass.from_fileobj(fh, **kw)

            if cmd_load.cmd in (LC_SEGMENT, LC_SEGMENT_64):
                # for segment commands, read the list of segments
                # assert that the size makes sense
                if cmd_load.cmd == LC_SEGMENT:
                    section_cls = section
                else: # LC_SEGMENT_64
                    section_cls = section_64

                expected_size = (
                    sizeof(klass) + sizeof(load_command) +
                    (sizeof(section_cls) * cmd_cmd.nsects)
                )
                if cmd_load.cmdsize != expected_size:
                    raise ValueError("Segment size mismatch")
                # this is a zero block or something
                # so the beginning is wherever the fileoff of this command is
                if not sectname:
                    if cmd_cmd.describe()["segname"] == segname:
                        #print hex(cmd_cmd.describe()["vmaddr"])
                        return cmd_cmd.describe()["vmaddr"]

                if cmd_cmd.nsects == 0:
                    if cmd_cmd.filesize != 0:
                        low_offset = min(low_offset, cmd_cmd.fileoff)
                else:
                    # this one has multiple segments
                    for j in range(cmd_cmd.nsects):
                        # read the segment
                        seg = section_cls.from_fileobj(fh, **kw)
                        if seg.describe()["segname"] == segname and seg.describe()["sectname"] == sectname:
                            #print hex(seg.describe()["addr"])
                            return seg.describe()["addr"]

                        """
                        self.section_details[seg.describe()["segname"] + "," + seg.describe()["sectname"]] =\
                            {"offset":seg.describe()["offset"], "size":seg.describe()["size"],
                             "addr":seg.describe()["addr"]}
                        """
                        # if the segment has a size and is not zero filled
                        # then its beginning is the offset of this segment
                        not_zerofill = ((seg.flags & S_ZEROFILL) != S_ZEROFILL)
                        if seg.offset > 0 and seg.size > 0 and not_zerofill:
                            low_offset = min(low_offset, seg.offset)
                        if not_zerofill:
                            c = fh.tell()
                            fh.seek(seg.offset)
                            sd = fh.read(seg.size)
                            seg.add_section_data(sd)
                            fh.seek(c)

            read_bytes += cmd_load.cmdsize

        # make sure the header made sense
        if read_bytes != header.sizeofcmds:
            raise ValueError("Read %d bytes, header reports %d bytes" % (
                read_bytes, header.sizeofcmds))
        return 0

    def macho_get_fileaddr(self, segname, sectname):
        fh = self.fh
        fh.seek(0)

        self.sizediff = 0
        kw = {'_endian_': self.endian}
        header = self.mach_header.from_fileobj(fh, **kw)

        read_bytes = 0
        low_offset = sys.maxsize
        for i in range(header.ncmds):
            # read the load command
            cmd_load = load_command.from_fileobj(fh, **kw)
            # read the specific command
            klass = LC_REGISTRY.get(cmd_load.cmd, None)

            if klass is None:
                raise ValueError("Unknown load command: %d" % (cmd_load.cmd,))
            cmd_cmd = klass.from_fileobj(fh, **kw)

            if cmd_load.cmd in (LC_SEGMENT, LC_SEGMENT_64):
                # for segment commands, read the list of segments
                # assert that the size makes sense
                if cmd_load.cmd == LC_SEGMENT:
                    section_cls = section
                else: # LC_SEGMENT_64
                    section_cls = section_64

                expected_size = (
                    sizeof(klass) + sizeof(load_command) +
                    (sizeof(section_cls) * cmd_cmd.nsects)
                )
                if cmd_load.cmdsize != expected_size:
                    raise ValueError("Segment size mismatch")
                # this is a zero block or something
                # so the beginning is wherever the fileoff of this command is
                if sectname == "":
                    if cmd_cmd.describe()["segname"] == segname:
                        #print hex(cmd_cmd.describe()["fileoff"])
                        return cmd_cmd.describe()["fileoff"]

                if cmd_cmd.nsects == 0:
                    if cmd_cmd.filesize != 0:
                        low_offset = min(low_offset, cmd_cmd.fileoff)
                else:
                    # this one has multiple segments
                    for j in range(cmd_cmd.nsects):
                        # read the segment
                        seg = section_cls.from_fileobj(fh, **kw)
                        if seg.describe()["segname"] == segname and seg.describe()["sectname"] == sectname:
                            #print hex(seg.describe()["offset"])
                            return seg.describe()["offset"]

                        """
                        self.section_details[seg.describe()["segname"] + "," + seg.describe()["sectname"]] =\
                            {"offset":seg.describe()["offset"], "size":seg.describe()["size"],
                             "addr":seg.describe()["addr"]}
                        """
                        # if the segment has a size and is not zero filled
                        # then its beginning is the offset of this segment
                        not_zerofill = ((seg.flags & S_ZEROFILL) != S_ZEROFILL)
                        if seg.offset > 0 and seg.size > 0 and not_zerofill:
                            low_offset = min(low_offset, seg.offset)
                        if not_zerofill:
                            c = fh.tell()
                            fh.seek(seg.offset)
                            sd = fh.read(seg.size)
                            seg.add_section_data(sd)
                            fh.seek(c)

            if cmd_load.cmd in [LC_SYMTAB]:
                if segname == "__SYMTAB" and sectname == "":
                    return cmd_cmd.describe()["symoff"]
                if segname == "__STRINGTAB" and sectname == "":
                    return cmd_cmd.describe()["stroff"]

            if cmd_load.cmd in [LC_DYSYMTAB]:
                if segname == "__DYSYMTAB" and sectname == "":
                    return cmd_cmd.describe()["extreloff"]

            read_bytes += cmd_load.cmdsize

        # make sure the header made sense
        if read_bytes != header.sizeofcmds:
            raise ValueError("Read %d bytes, header reports %d bytes" % (
                read_bytes, header.sizeofcmds))
        return 0

    def macho_get_size(self, segname, sectname):
        fh = self.fh
        fh.seek(0)

        self.sizediff = 0
        kw = {'_endian_': self.endian}
        header = self.mach_header.from_fileobj(fh, **kw)

        read_bytes = 0
        low_offset = sys.maxsize
        for i in range(header.ncmds):
            # read the load command
            cmd_load = load_command.from_fileobj(fh, **kw)
            # read the specific command
            klass = LC_REGISTRY.get(cmd_load.cmd, None)

            if klass is None:
                raise ValueError("Unknown load command: %d" % (cmd_load.cmd,))
            cmd_cmd = klass.from_fileobj(fh, **kw)

            if cmd_load.cmd in (LC_SEGMENT, LC_SEGMENT_64):
                # for segment commands, read the list of segments
                # assert that the size makes sense
                if cmd_load.cmd == LC_SEGMENT:
                    section_cls = section
                else: # LC_SEGMENT_64
                    section_cls = section_64

                expected_size = (
                    sizeof(klass) + sizeof(load_command) +
                    (sizeof(section_cls) * cmd_cmd.nsects)
                )
                if cmd_load.cmdsize != expected_size:
                    raise ValueError("Segment size mismatch")
                # this is a zero block or something
                # so the beginning is wherever the fileoff of this command is
                if sectname == "":
                    if cmd_cmd.describe()["segname"] == segname:
                        #print hex(cmd_cmd.describe()["filesize"])
                        return cmd_cmd.describe()["filesize"]

                if cmd_cmd.nsects == 0:
                    if cmd_cmd.filesize != 0:
                        low_offset = min(low_offset, cmd_cmd.fileoff)
                else:
                    # this one has multiple segments
                    for j in range(cmd_cmd.nsects):
                        # read the segment
                        seg = section_cls.from_fileobj(fh, **kw)
                        if seg.describe()["segname"] == segname and seg.describe()["sectname"] == sectname:
                            #print hex(seg.describe()["size"])
                            return seg.describe()["size"]

                        """
                        self.section_details[seg.describe()["segname"] + "," + seg.describe()["sectname"]] =\
                            {"offset":seg.describe()["offset"], "size":seg.describe()["size"],
                             "addr":seg.describe()["addr"]}
                        """
                        # if the segment has a size and is not zero filled
                        # then its beginning is the offset of this segment
                        not_zerofill = ((seg.flags & S_ZEROFILL) != S_ZEROFILL)
                        if seg.offset > 0 and seg.size > 0 and not_zerofill:
                            low_offset = min(low_offset, seg.offset)
                        if not_zerofill:
                            c = fh.tell()
                            fh.seek(seg.offset)
                            sd = fh.read(seg.size)
                            seg.add_section_data(sd)
                            fh.seek(c)

            if cmd_load.cmd in [LC_SYMTAB]:
                if segname == "__SYMTAB" and sectname == "":
                    return cmd_cmd.describe()["nsyms"]
                if segname == "__STRINGTAB" and sectname == "":
                    return cmd_cmd.describe()["strsize"]

            if cmd_load.cmd in [LC_DYSYMTAB]:
                if segname == "__DYSYMTAB" and sectname == "":
                    return cmd_cmd.describe()["nextrel"]

            read_bytes += cmd_load.cmdsize

        # make sure the header made sense
        if read_bytes != header.sizeofcmds:
            raise ValueError("Read %d bytes, header reports %d bytes" % (
                read_bytes, header.sizeofcmds))
        return 0

    def macho_get_loadcmds(self):
        loadcmds = {}
        index = 1
        fh = self.fh
        fh.seek(0)

        self.sizediff = 0
        kw = {'_endian_': self.endian}
        header = self.mach_header.from_fileobj(fh, **kw)

        read_bytes = 0
        low_offset = sys.maxsize
        for i in range(header.ncmds):
            # read the load command
            cmd_load = load_command.from_fileobj(fh, **kw)
            # read the specific command
            klass = LC_REGISTRY.get(cmd_load.cmd, None)
            if klass is None:
                raise ValueError("Unknown load command: %d" % (cmd_load.cmd,))
            cmd_cmd = klass.from_fileobj(fh, **kw)

            if cmd_load.cmd in (LC_SEGMENT, LC_SEGMENT_64):
                # for segment commands, read the list of segments
                # assert that the size makes sense
                if cmd_load.cmd == LC_SEGMENT:
                    section_cls = section
                else:  # LC_SEGMENT_64
                    section_cls = section_64

                expected_size = (
                    sizeof(klass) + sizeof(load_command) +
                    (sizeof(section_cls) * cmd_cmd.nsects)
                )
                if cmd_load.cmdsize != expected_size:
                    raise ValueError("Segment size mismatch")
                # this is a zero block or something
                # so the beginning is wherever the fileoff of this command is
                if cmd_cmd.nsects == 0:
                    if cmd_cmd.filesize != 0:
                        low_offset = min(low_offset, cmd_cmd.fileoff)
                else:
                    # this one has multiple segments
                    for j in range(cmd_cmd.nsects):
                        # read the segment
                        seg = section_cls.from_fileobj(fh, **kw)
                        loadcmds[index] = seg.describe()["segname"] + ", " + seg.describe()["sectname"]
                        index += 1

                        # if the segment has a size and is not zero filled
                        # then its beginning is the offset of this segment
                        not_zerofill = ((seg.flags & S_ZEROFILL) != S_ZEROFILL)
                        if seg.offset > 0 and seg.size > 0 and not_zerofill:
                            low_offset = min(low_offset, seg.offset)
                        if not_zerofill:
                            c = fh.tell()
                            fh.seek(seg.offset)
                            sd = fh.read(seg.size)
                            seg.add_section_data(sd)
                            fh.seek(c)

            read_bytes += cmd_load.cmdsize

        # make sure the header made sense
        if read_bytes != header.sizeofcmds:
            raise ValueError("Read %d bytes, header reports %d bytes" % (
                read_bytes, header.sizeofcmds))
        return loadcmds

    def memcpy(self, start_fileaddr, size):
        fh = self.fh
        fh.seek(start_fileaddr)
        if size == 8:
            return struct.unpack('<Q', fh.read(8))[0]
        elif size == 4:
            return struct.unpack('<I', fh.read(4))[0]
        elif size == 1:
            return struct.unpack('<B', fh.read(1))[0]
        else:
            return fh.read(size)

    def get_mem_from_vmaddr(self, anchor_f, anchor_vm, src_vm):
        addr = anchor_f + (src_vm - anchor_vm)
        return self.memcpy(addr, 8)

    def get_memStr_from_vmaddr(self, anchor_f, anchor_vm, src_vm):
        addr = anchor_f + (src_vm - anchor_vm)
        data_str = ""
        fh = self.fh
        fh.seek(addr)
        while True:
            data = fh.read(1)
            # \x00 is the split flag in cstring section
            if data == "\x00":
                break
            data_str += data
        return data_str

    def get_memStr_from_f(self, file_off):
        addr = file_off
        data_str = ""
        fh = self.fh
        fh.seek(addr)
        while True:
            data = fh.read(1)
            # \x00 is the split flag in cstring section
            if data == "\x00":
                break
            data_str += data
        return data_str

    def get_f_from_vm(self, anchor_f, anchor_vm, src_vm):
        return anchor_f + (src_vm - anchor_vm)

    def get_vm_from_f(self, anchor_f, anchor_vm, src_f):
        return anchor_vm + (src_f - anchor_f)

    def get_prelinkf_from_vm(self, src_vm):
        return src_vm - self.prelink_offset

    def get_prelinkvm_from_f(self, anchor_vm, anchor_f, src_f):
        return src_f + (anchor_vm - anchor_f)


if __name__ == '__main__':
    macho_file = open("/home/wdy/ipsw/kernel_cache/kernel_10_3_2", "rb")
    macho_file.seek(0, 2)
    size = macho_file.tell()
    macho_file.seek(0)
    macho_header = MachOHeader(macho_file, 0, size)
    macho_header.macho_get_vmaddr("__DATA_CONST", "__mod_init_func")
    macho_header.macho_get_fileaddr("__DATA_CONST", "__mod_init_func")
    macho_header.macho_get_size("__DATA_CONST", "__mod_init_func")
    macho_header.macho_get_fileaddr("__TEXT_EXEC", "__text")
    macho_header.macho_get_size("__TEXT_EXEC", "__text")
    macho_header.memcpy("", 8)