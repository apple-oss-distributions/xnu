import macholib
from macholib import MachO as macho
from collections import namedtuple
import uuid
import sys


#
# Defines segment/section descriptions that can be used by external users
# like kext management to keep track about memory layout. To avoid the need
# to keep full Mach-O instance around.
#

MachOSegment = namedtuple(
    'MachOSegment',
    'name vmaddr vmsize fileoff filesize sections'
)

MachOSection = namedtuple(
    'MachOSection',
    'sectname addr size fileoff'
)


#
# The Mach-O library loads data for each section in a Mach-O.
# This breaks our macros in few ways:
#   - It is slow and no one is really using it.
#   - File offsets in fileset KC points outside of the file window reported
#     by OSkext API.
#
# Until macholib gets some optin to avoid reading section data we have to
# patch it here.
# 
# !!! Note. This works only with the latest lib 1.15.1 !!!

if macholib.__version__ == "1.15.2":
    from macholib.mach_o import (
        LC_ID_DYLIB,
        LC_REGISTRY,
        LC_SEGMENT,
        LC_SEGMENT_64,
        S_ZEROFILL,
        load_command,
        section,
        section_64,
    )
    from macholib.ptypes import sizeof
    from macholib.util import fileview


    # !!! This is the actual patch for macholib 1.15.2 !!!
    #
    #   1. MemMachOHeader subclasses macho.MachOHeader
    #   2. Overloaded load() method is copy/paste of the original load() with
    #      small patch added that disables section contents loading.
    #   3. The new MemMachOHeader is injected back into library and used
    #      in place of macho.MachOHeader.
    #
    # This code should not ever exist in the first place. So the plan is to
    # remove it when macholib gets improved or abandoned by our own
    # implementation.
    class MemMachOHeader(macho.MachOHeader):
        """ Mach-O header parser that does not try to load section data. """

        def load(self, fh):
            fh = fileview(fh, self.offset, self.size)
            fh.seek(0)

            self.sizediff = 0
            kw = {"_endian_": self.endian}
            header = self.mach_header.from_fileobj(fh, **kw)
            self.header = header
            # If header.magic != self.MH_MAGIC:
            #    raise ValueError("header has magic %08x, expecting %08x" % (
            #        header.magic, self.MH_MAGIC))

            cmd = self.commands = []

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
                    else:  # LC_SEGMENT_64
                        section_cls = section_64

                    expected_size = (
                        sizeof(klass)
                        + sizeof(load_command)
                        + (sizeof(section_cls) * cmd_cmd.nsects)
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
                        for _j in range(cmd_cmd.nsects):
                            # read the segment
                            seg = section_cls.from_fileobj(fh, **kw)
                            # If the segment has a size and is not zero filled
                            # then its beginning is the offset of this segment
                            not_zerofill = (seg.flags & S_ZEROFILL) != S_ZEROFILL
                            if seg.offset > 0 and seg.size > 0 and not_zerofill:
                                low_offset = min(low_offset, seg.offset)

                            # Do NOT read section data. It is not required and
                            # does not work well with filset KC offsets.
                            """
                            if not_zerofill:
                                c = fh.tell()
                                fh.seek(seg.offset)
                                sd = fh.read(seg.size)
                                seg.add_section_data(sd)
                                fh.seek(c)
                            """
                            segs.append(seg)
                    # data is a list of segments
                    cmd_data = segs

                else:
                    # data is a raw str
                    data_size = cmd_load.cmdsize - sizeof(klass) - sizeof(load_command)
                    cmd_data = fh.read(data_size)
                cmd.append((cmd_load, cmd_cmd, cmd_data))
                read_bytes += cmd_load.cmdsize

            # make sure the header made sense
            if read_bytes != header.sizeofcmds:
                raise ValueError(
                    "Read %d bytes, header reports %d bytes"
                    % (read_bytes, header.sizeofcmds)
                )
            self.total_size = sizeof(self.mach_header) + read_bytes
            self.low_offset = low_offset


    # Patch the library to use our own header class instead.
    macho.MachOHeader = MemMachOHeader


class MemMachO(macho.MachO):
    """ Mach-O implementation that accepts I/O stream instead of file. """

    def __init__(self, file):
        """ Creates Mach-O parser on top of provided I/O. """

        # Figured out file size from the I/O.
        file.seek(0, 2)
        size = file.tell()
        file.seek(0, 0)

        # supports the ObjectGraph protocol
        self.graphident = 'mem:%d//'.format(size)
        self.filename = 'mem:%d//'.format(size)
        self.loader_path = "<no-path>"

        # initialized by load
        self.fat = None
        self.headers = []

        self.load(file)

    @staticmethod
    def make_seg(seg, sects):
        """ Constructs MachOSegment from input. """

        # Wrap all sections in MachOSection tuple.
        segsec = [
            MachOSection(
                sectname = s.segname[:s.segname.find(b'\x00')].decode(),
                addr = s.addr,
                fileoff = s.offset,
                size = s.size
            )
            for s in sects
        ]

        # Return MachOSegment
        return MachOSegment(
            name=seg.segname[:seg.segname.find(b'\x00')].decode(),
            vmaddr = seg.vmaddr,
            vmsize = seg.vmsize,
            fileoff = seg.fileoff,
            filesize = seg.filesize,
            sections = segsec
        )

    @property
    def segments(self):
        """ Constructs section/segment descriptors.

            Values are cached in an instance attribute.
        """
        if hasattr(self, '_segments'):
            return self._segments

        # Wrap all segments/sections into a MachOSegment/MachOSection.
        self._segments = [
            self.make_seg(seg, sec)
            for h in self.headers
            for _, seg, sec in h.commands
            if isinstance(seg, SEGMENT_TYPES)
        ]

        return self._segments

    @property
    def uuid(self):
        """ Returns UUID of the Mach-O. """
        if hasattr(self, '_uuid'):
            return self._uuid

        for h in self.headers:
            for cmd in h.commands:
                # cmds is [(load_command, segment, [sections..])]
                (_, segment, _) = cmd
                if isinstance(segment, macholib.mach_o.uuid_command):
                    self._uuid = str(uuid.UUID(bytes=segment.uuid)).upper()
        return self._uuid


# some fixups in macholib that are required for kext support
macholib.mach_o.MH_KEXT_BUNDLE = 0xB

macholib.mach_o.MH_FILETYPE_NAMES[macholib.mach_o.MH_KEXT_BUNDLE] = "kext bundle"
macholib.mach_o.MH_FILETYPE_SHORTNAMES[macholib.mach_o.MH_KEXT_BUNDLE] = "kext"

SEGMENT_TYPES = (macholib.mach_o.segment_command_64, macholib.mach_o.segment_command)

def get_load_command_human_name(lc):
    return lc.get_cmd_name()


class VisualMachoMap(object):
    KB_1 = 1024
    KB_16 = 16 * 1024
    MB_1 = 1 * 1024 * 1024
    GB_1 = 1 * 1024 * 1024 * 1024

    def __init__(self, name, width=40):
        self.name = name
        self.width = 40
        self.default_side_padding = 2

    def get_header_line(self):
        return '+' + '-' * (self.width - 2) + '+'

    def get_space_line(self):
        return '|' + ' ' * (self.width - 2) + '|'

    def get_dashed_line(self):
        return '|' + '-' * (self.width - 2) + '|'

    def get_dotted_line(self):
        return '|' + '.' * (self.width - 2) + '|'

    def center_text_in_line(self, line, text):
        even_length = bool(len(text) % 2 == 0)
        if len(text) > len(line) - 2:
            raise ValueError("text is larger than line of text")

        lbreak_pos = (len(line) // 2) - (len(text) // 2)
        if not even_length:
            lbreak_pos -= 1
        out = line[:lbreak_pos] + text
        return out + line[len(out):]

    def get_separator_lines(self):
        return ['/' + ' ' * (self.width - 2) + '/', '/' + ' ' * (self.width - 2) + '/']

    def printMachoMap(self, mobj):
        MapBlock = namedtuple('MapBlock', 'name vmaddr vmsize fileoff filesize extra_info is_segment')
        outstr = self.name + '\n'
        other_cmds = ''
        blocks = []
        for hdr in mobj.headers:
            cmd_index = 0
            for cmd in hdr.commands:
                # cmds is [(load_command, segment, [sections..])]
                (lc, segment, sections) = cmd
                lc_cmd_str = get_load_command_human_name(lc)
                lc_str_rep = "\n\t LC: {:s} size:{:d} nsects:{:d}".format(lc_cmd_str, lc.cmdsize, len(sections))
                # print lc_str_rep
                if isinstance(segment, SEGMENT_TYPES):
                    segname = segment.segname[:segment.segname.find(b'\x00')].decode()
                    # print "\tsegment: {:s} vmaddr: {:x} vmsize:{:d} fileoff: {:x} filesize: {:d}".format(
                    #             segname, segment.vmaddr, segment.vmsize, segment.fileoff, segment.filesize)
                    blocks.append(MapBlock(segname, segment.vmaddr, segment.vmsize, segment.fileoff, segment.filesize,
                                            ' LC:{} : {} init:{:#0X} max:{:#0X}'.format(lc_cmd_str, segname, segment.initprot, segment.maxprot),
                                            True))
                    for section in sections:
                        section_name = section.sectname[:section.sectname.find(b'\x00')].decode()
                        blocks.append(MapBlock(section_name, section.addr, section.size, section.offset,
                                                section.size, 'al:{} flags:{:#0X}'.format(section.align, section.flags), False))
                        #print "\t\tsection:{:s} addr:{:x} off:{:x} size:{:d}".format(section_name, section.addr, section.offset, section.size)
                elif isinstance(segment, macholib.mach_o.uuid_command):
                    other_cmds += "\n\t uuid: {:s}".format(str(uuid.UUID(bytes=segment.uuid)).upper())
                elif isinstance(segment, macholib.mach_o.rpath_command):
                    other_cmds += "\n\t rpath: {:s}".format(segment.path)
                elif isinstance(segment, macholib.mach_o.dylib_command):
                    other_cmds += "\n\t dylib: {:s} ({:s})".format(str(sections[:sections.find(b'\x00')]), str(segment.current_version))
                else:
                    other_cmds += lc_str_rep
                cmd_index += 1

        # fixup the self.width param
        for _b in blocks:
            if self.default_side_padding + len(_b.name) + 2 > self.width:
                self.width = self.default_side_padding + len(_b.name) + 2
        if self.width % 2 != 0:
            self.width += 1

        sorted_blocks = sorted(blocks, key=lambda b: b.vmaddr)
        mstr = [self.get_header_line()]
        prev_block = MapBlock('', 0, 0, 0, 0, '', False)
        for b in sorted_blocks:
            # TODO add separator blocks if vmaddr is large from prev_block
            if b.is_segment:
                s = self.get_dashed_line()
            else:
                s = self.get_dotted_line()
            s = self.center_text_in_line(s, b.name)
            line = "{:s} {: <#020X} ({: <10d}) floff:{: <#08x}  {}".format(s, b.vmaddr, b.vmsize, b.fileoff, b.extra_info)
            if (b.vmaddr - prev_block.vmaddr) > VisualMachoMap.KB_16:
                mstr.append(self.get_space_line())
                mstr.append(self.get_space_line())

            mstr.append(line)

            if b.vmsize > VisualMachoMap.MB_1:
                mstr.append(self.get_space_line())
                mstr.extend(self.get_separator_lines())
                mstr.append(self.get_space_line())
            #mstr.append(self.get_space_line())
            prev_block = b
        mstr.append(self.get_space_line())
        if prev_block.vmsize > VisualMachoMap.KB_16:
            mstr.append(self.get_space_line())
        mstr.append(self.get_header_line())
        print(outstr)
        print("\n".join(mstr))
        print("\n\n=============== Other Load Commands ===============")
        print(other_cmds)


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: {} /path/to/macho_binary".format(sys.argv[0]))
        sys.exit(1)
    with open(sys.argv[-1], 'rb') as fp:
        mobject = MemMachO(fp)

        p = VisualMachoMap(sys.argv[-1])
        p.printMachoMap(mobject)
    sys.exit(0)
