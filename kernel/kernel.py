

import os
import sys
import struct
import os
import json
import getopt


from lib.mach_o import *
from lib.util import fileview
import xml.etree.ElementTree as ET



if sys.version_info[0] == 2:
    range = xrange

__all__ = ['MachO']

_RELOCATABLE = set((
    # relocatable commands that should be used for dependency walking
    LC_LOAD_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_PREBOUND_DYLIB,
    LC_REEXPORT_DYLIB,
    ))

_RELOCATABLE_NAMES = {
    LC_LOAD_DYLIB: 'load_dylib',
    LC_LOAD_UPWARD_DYLIB: 'load_upward_dylib',
    LC_LOAD_WEAK_DYLIB: 'load_weak_dylib',
    LC_PREBOUND_DYLIB: 'prebound_dylib',
    LC_REEXPORT_DYLIB: 'reexport_dylib',
}

def _shouldRelocateCommand(cmd):
    return cmd in _RELOCATABLE

class KernelMachO(object):

    def __init__(self, filename=None, base_addr=0xfffffff007004000):
        self.base_addr = base_addr
        self.filename = filename
        self.loader_path = os.path.dirname(filename)
        self.fat = None
        self.headers = []
        self.is64bit = False
        self.isfat = False

        self.driver_list_prelink = []
        self.driver_list_notprelink = []

        if filename is not None:
            self.macho_file = open(filename, "rb")
            self.macho_file.seek(0, 2)
            self.size = self.macho_file.tell()
            self.macho_file.seek(0)
            #with open(filename, "rb") as macho_file:
            self.load(self.macho_file)
        else:
            self.macho_file = None
            self.size = 0

    def load(self, fh):
        assert fh.tell() == 0
        header = struct.unpack('<I', fh.read(4))[0]
        fh.seek(0)
        if header in (FAT_MAGIC, FAT_MAGIC_64):
            self.isfat = True
            self.load_fat(fh)
        else:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(0)
            self.load_header(fh, 0, size)

    def load_fat(self, fh):
        self.fat = fat_header.from_fileobj(fh)
        if self.fat.magic == FAT_MAGIC:
            archs = [fat_arch.from_fileobj(fh) for i in range(self.fat.nfat_arch)]
        elif self.fat.magic == FAT_MAGIC_64:
            archs = [fat_arch64.from_fileobj(fh) for i in range(self.fat.nfat_arch)]
        else:
            raise ValueError("Unknown fat header magic: %r"%(self.fat.magic))
        for arch in archs:
            self.load_header(fh, arch.offset, arch.size)

    def load_header(self, fh, offset, size):
        fh.seek(offset)
        header = struct.unpack('<I', fh.read(4))[0]
        fh.seek(offset)
        if header == MH_MAGIC:
            magic, hdr, endian = MH_MAGIC, mach_header, '<'
        elif header == MH_CIGAM:
            magic, hdr, endian = MH_CIGAM, mach_header, '>'
        elif header == MH_MAGIC_64:
            magic, hdr, endian = MH_MAGIC_64, mach_header_64, '<'
            self.is64bit = True
        elif header == MH_CIGAM_64:
            magic, hdr, endian = MH_CIGAM_64, mach_header_64, '>'
        else:
            raise ValueError("Unknown Mach-O header: 0x%08x in %r" % (
                header, fh))
        hdr = MachOHeader(self, fh, offset, size, magic, hdr, endian)
        self.headers.append(hdr)

    def get_section_addrs(self):
        if not self.isfat and self.is64bit:
            return self.headers[0].section_details
        else:
            print "file %s is fat or 32bit" % self.filename

    def get_other_addrs(self):
        if not self.isfat and self.is64bit:
            return self.headers[0].other_segment_details
        else:
            print "file %s is fat or 32bit" % self.filename

    def get_driver_list(self):
        driver_list_prelink = self.driver_list_prelink = []
        driver_list_notprelink = self.driver_list_notprelink = []
        fh = self.macho_file
        if "__PRELINK_INFO,__info" not in self.get_section_addrs():
            return None

        sec_addr = self.get_section_addrs()["__PRELINK_INFO,__info"]["offset"]
        sec_size = self.get_section_addrs()["__PRELINK_INFO,__info"]["size"]
        size = 0
        section = ""
        fh.seek(sec_addr)
        while size < sec_size:
            sect = struct.unpack('>B', fh.read(1))[0]
            if sect == 0:
                break
            section += hex(sect).replace("0x", "").replace("L", "").decode("hex")#binascii.a2b_hex(hex(sect).replace("0x", ""))
            sec_addr += 1
            size += 1
            fh.seek(sec_addr)
        #CommonTool.save_file("/home/wdy/ipsw/ipsw-tools/kext.xml", section)
        #tree = ET.ElementTree(file="/home/wdy/ipsw/ipsw-tools/kext.xml")
        tree = ET.fromstring(section)
        for bundle in tree.iterfind("array/dict"):
            driver_dict = {}
            driver_details = self.__parser_driver_dict(ET.tostring(bundle))
            if "_PrelinkKmodInfo" in driver_details:
                driver_name = (driver_details["CFBundleName"], driver_details["CFBundleIdentifier"],
                               driver_details["_PrelinkKmodInfo"])
            else:
                driver_name = (driver_details["CFBundleName"], driver_details["CFBundleIdentifier"],
                               None)
            if "_PrelinkExecutableLoadAddr" in driver_details:
                driver_dict[driver_details["_PrelinkExecutableLoadAddr"]] = driver_name
                driver_list_prelink.append(driver_dict)
            else:
                driver_dict["0x0000000000000000"] = driver_name
                driver_list_notprelink.append(driver_dict)
        #print driver_list_prelink, driver_list_notprelink
        return driver_list_prelink, driver_list_notprelink

    def extract_kext(self, bundleID=None, dir=None):
        for driver in self.driver_list_notprelink:
            for addr, details in driver.iteritems():
                if bundleID in details:
                    print "kext %s is not prelink in the kernelcache!" % bundleID
                    return None

        # get the correction offset
        prelink_text = self.get_section_addrs()["__PRELINK_TEXT,__text"]
        prelink_offset = prelink_text["addr"] - prelink_text["offset"]
        start_addr = ""
        data_addr = ""
        for i in range(len(self.driver_list_prelink)):
            for addr, details in self.driver_list_prelink[i].iteritems():
                if bundleID in details:
                    start_addr = addr
                    #if details[2] is not None and details[2] != "0x0":    removed because they are all pseudo kext
                    data_addr = details[2]
                    break
        if start_addr and data_addr:
            header_offset = (eval(start_addr) - prelink_offset)
            self.__construct_kext(bundleID, header_offset, prelink_offset, dir)

    def __construct_kext(self, bundle, offset, prelink_offset, dir):
        fh = self.macho_file
        fh.seek(offset)
        header = struct.unpack('<I', fh.read(4))[0]
        fh.seek(offset)
        if header == MH_MAGIC:
            magic, hdr, endian = MH_MAGIC, mach_header, '<'
        elif header == MH_CIGAM:
            magic, hdr, endian = MH_CIGAM, mach_header, '>'
        elif header == MH_MAGIC_64:
            magic, hdr, endian = MH_MAGIC_64, mach_header_64, '<'
            self.is64bit = True
        elif header == MH_CIGAM_64:
            magic, hdr, endian = MH_CIGAM_64, mach_header_64, '>'
        else:
            raise ValueError("Unknown Mach-O header: 0x%08x in %r" % (
                header, fh))

        # only support 64bit
        kext_file = bundle + ".kext"
        if dir:
            kext_file = dir + os.sep + kext_file
        fd = open(kext_file, 'wb')
        hdr = MachOHeader(self, fh, offset, self.size, magic, hdr, endian)
        self.__dump_kext_data(fd, offset, hdr.total_size, 0)
        for section, details in hdr.section_details.iteritems():
            fh_offset = details["addr"] - prelink_offset
            size = details["size"]
            fd_offset = details["offset"]
            self.__dump_kext_data(fd, fh_offset, size, fd_offset)

    def __dump_kext_data(self, fd, fh_offset, data_size, fd_offset):
        fh = self.macho_file
        fh.seek(fh_offset)
        fd.seek(fd_offset)
        fd.write(fh.read(data_size))

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


class MachOHeader(object):

    def __init__(self, parent, fh, offset, size, magic, hdr, endian):
        self.MH_MAGIC = magic
        self.mach_header = hdr

        # These are all initialized by self.load()
        self.parent = parent
        self.offset = offset
        self.size = size

        self.endian = endian
        self.header = None
        self.commands = None
        self.id_cmd = None
        self.sizediff = None
        self.total_size = None
        self.low_offset = None
        self.filetype = None
        self.headers = []

        self.cmd = []
        self.section_details = {}
        self.other_segment_details = {}
        self.segs = []

        self.load(fh)


    def load(self, fh):
        fh = fileview(fh, self.offset, self.size)
        fh.seek(0)

        self.sizediff = 0
        kw = {'_endian_': self.endian}
        header = self.mach_header.from_fileobj(fh, **kw)
        self.header = header
        #print hex(header.magic)
        #if header.magic != self.MH_MAGIC:
        #    raise ValueError("header has magic %08x, expecting %08x" % (
        #        header.magic, self.MH_MAGIC))

        self.cmd = self.commands = []
        self.filetype = self.get_filetype_shortname(header.filetype)
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

            #print LC_NAMES[cmd_load.cmd]
            if cmd_load.cmd == LC_ID_DYLIB:
                # remember where this command was
                if self.id_cmd is not None:
                    raise ValueError("This dylib already has an id")
                self.id_cmd = i

            if cmd_load.cmd in (LC_SEGMENT, LC_SEGMENT_64):
                # for segment commands, read the list of segments
                segs = []
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
                if cmd_cmd.nsects == 0:
                    if cmd_cmd.filesize != 0:
                        self.other_segment_details[cmd_cmd.describe()["segname"]] =\
                            {"offset":cmd_cmd.describe()["fileoff"], "size":cmd_cmd.describe()["vmsize"]}
                        low_offset = min(low_offset, cmd_cmd.fileoff)
                else:
                    # this one has multiple segments
                    for j in range(cmd_cmd.nsects):
                        # read the segment
                        seg = section_cls.from_fileobj(fh, **kw)
                        self.section_details[seg.describe()["segname"] + "," + seg.describe()["sectname"]] =\
                            {"offset":seg.describe()["offset"], "size":seg.describe()["size"],
                             "addr":seg.describe()["addr"]}
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
                        segs.append(seg)
                # data is a list of segments
                cmd_data = segs
            else:
                # data is a raw str
                #self.other_segment_details[LC_NAMES[cmd_load.cmd]] =
                #print klass
                data_size = (
                    cmd_load.cmdsize - sizeof(klass) - sizeof(load_command)
                )
                cmd_data = fh.read(data_size)
            self.cmd.append((cmd_load, cmd_cmd, cmd_data))

            read_bytes += cmd_load.cmdsize

        # make sure the header made sense
        if read_bytes != header.sizeofcmds:
            raise ValueError("Read %d bytes, header reports %d bytes" % (
                read_bytes, header.sizeofcmds))
        self.total_size = sizeof(self.mach_header) + read_bytes
        self.low_offset = low_offset

    def walkRelocatables(self, shouldRelocateCommand=_shouldRelocateCommand):
        """
        for all relocatable commands
        yield (command_index, command_name, filename)
        """
        for (idx, (lc, cmd, data)) in enumerate(self.commands):
            if shouldRelocateCommand(lc.cmd):
                name = _RELOCATABLE_NAMES[lc.cmd]
                ofs = cmd.name - sizeof(lc.__class__) - sizeof(cmd.__class__)
                yield idx, name, data[ofs:data.find(b'\x00', ofs)].decode(
                        sys.getfilesystemencoding())

    def rewriteInstallNameCommand(self, loadcmd):
        """Rewrite the load command of this dylib"""
        if self.id_cmd is not None:
            self.rewriteDataForCommand(self.id_cmd, loadcmd)
            return True
        return False

    def changedHeaderSizeBy(self, bytes):
        self.sizediff += bytes
        if (self.total_size + self.sizediff) > self.low_offset:
            print("WARNING: Mach-O header in %r may be too large to relocate"%(self.parent.filename,))

    def rewriteLoadCommands(self, changefunc):
        """
        Rewrite the load commands based upon a change dictionary
        """
        data = changefunc(self.parent.filename)
        changed = False
        if data is not None:
            if self.rewriteInstallNameCommand(
                    data.encode(sys.getfilesystemencoding())):
                changed = True
        for idx, name, filename in self.walkRelocatables():
            data = changefunc(filename)
            if data is not None:
                if self.rewriteDataForCommand(idx, data.encode(
                        sys.getfilesystemencoding())):
                    changed = True
        return changed

    def rewriteDataForCommand(self, idx, data):
        lc, cmd, old_data = self.commands[idx]
        hdrsize = sizeof(lc.__class__) + sizeof(cmd.__class__)
        align = struct.calcsize('Q')
        data = data + (b'\x00' * (align - (len(data) % align)))
        newsize = hdrsize + len(data)
        self.commands[idx] = (lc, cmd, data)
        self.changedHeaderSizeBy(newsize - lc.cmdsize)
        lc.cmdsize, cmd.name = newsize, hdrsize
        return True

    def synchronize_size(self):
        if (self.total_size + self.sizediff) > self.low_offset:
            raise ValueError("New Mach-O header is too large to relocate in %r (new size=%r, max size=%r, delta=%r)"%(
                self.parent.filename, self.total_size + self.sizediff, self.low_offset, self.sizediff))
        self.header.sizeofcmds += self.sizediff
        self.total_size = sizeof(self.mach_header) + self.header.sizeofcmds
        self.sizediff = 0

    def write(self, fileobj):
        fileobj = fileview(fileobj, self.offset, self.size)
        fileobj.seek(0)

        # serialize all the mach-o commands
        self.synchronize_size()

        self.header.to_fileobj(fileobj)
        for lc, cmd, data in self.commands:
            lc.to_fileobj(fileobj)
            cmd.to_fileobj(fileobj)

            if sys.version_info[0] == 2:
                if isinstance(data, unicode):
                    fileobj.write(data.encode(sys.getfilesystemencoding()))

                elif isinstance(data, (bytes, str)):
                    fileobj.write(data)
                else:
                    # segments..
                    for obj in data:
                        obj.to_fileobj(fileobj)
            else:
                if isinstance(data, str):
                    fileobj.write(data.encode(sys.getfilesystemencoding()))

                elif isinstance(data, bytes):
                    fileobj.write(data)

                else:
                    # segments..
                    for obj in data:
                        obj.to_fileobj(fileobj)

        # zero out the unused space, doubt this is strictly necessary
        # and is generally probably already the case
        fileobj.write(b'\x00' * (self.low_offset - fileobj.tell()))

    def getSymbolTableCommand(self):
        for lc, cmd, data in self.commands:
            if lc.cmd == LC_SYMTAB:
                return cmd
        return None

    def getDynamicSymbolTableCommand(self):
        for lc, cmd, data in self.commands:
            if lc.cmd == LC_DYSYMTAB:
                return cmd
        return None

    def get_filetype_shortname(self, filetype):
        if filetype in MH_FILETYPE_SHORTNAMES:
            return MH_FILETYPE_SHORTNAMES[filetype]
        else:
            return 'unknown'
