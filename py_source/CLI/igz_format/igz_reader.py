'''IGZ file reader - parses header, sections, fixup tables, and nodes.

IGZ is the Alchemy 6.0+ binary format used by MUA2 PC, Crash NST, etc.
It is NOT compressed IGB - it's a completely different binary format.

File layout:
  0x10 bytes:  Header (magic, version, platform, unused)
  0x10 bytes+: Pointer table (0x10 bytes each: offset, size, alignment, identifier)
  Padding:     and Memory pool name strings (null-terminated)
  Section 0:   Fixup section (metatype, reference and other tables)
  Section 1+:  Data sections (Default=nodes, Vertex, System, Image, ...)

Version differences:
  v6 (MUA2 PC): Fixup blocks in implicit order or ID, no ASCII tags, nibble decode uses +1
  v10 (Crash NST): Fixup blocks with 4-char ASCII tags, nibble decode without +1
'''

from collections.abc import Iterator
from dataclasses import dataclass, field, InitVar
from enum import Enum
from pathlib import Path
from struct import Struct, unpack_from
from typing import Any, Optional, BinaryIO
import numpy as np
import os

from igz_nodes import build_registry


# --- Constants ---

IGZ_MAGIC = 0x49475A01  # "\x01ZGI" in little-endian

# Fixed order of fixup blocks in v6 format (no ASCII tags - implied by position)
V6_FIXUP_ORDER = (
    'TSTR', 'TMET', 'MTSZ', 'EXNM', 'EXID',
    'RVTB', 'RSTT', 'ROFS', 'RPID', 'REXT',
    'RHND', 'ROOT', 'ONAM', 'NSPC',
)

# Inner header size for the fixup section (v6)
V6_FIXUP_INNER_HEADER_SIZE = 28


# --- Data classes ---

@dataclass(slots=True)
class ChunkInfo:
    """Describes a section/chunk in the IGZ file."""
    offset: int
    size: int
    alignment: int
    identifier: int
    name: str = ''


class IGZObject:
    """Represents a parsed object from the IGZ Default section."""
    __slots__ = (
        'type_name', 'type_index', 'type_size',
        'global_offset', 'raw_data',
        'references', 'object_name',
    )

    def __init__(self, type_name, type_index, type_size, global_offset):
        self.type_name = type_name
        self.type_index = type_index
        self.type_size = type_size
        self.global_offset = global_offset
        self.raw_data = None
        self.references = {}   # field_offset_within_object -> target IGZObject or int (global offset)
        self.object_name = None

    def read_u8(self, offset):
        return self.raw_data[offset]

    def read_u16(self, offset):
        return unpack_from('<H', self.raw_data, offset)[0]

    def read_i32(self, offset):
        return unpack_from('<i', self.raw_data, offset)[0]

    def read_u32(self, offset):
        return unpack_from('<I', self.raw_data, offset)[0]

    def read_u64(self, offset):
        return unpack_from('<Q', self.raw_data, offset)[0]

    def read_f32(self, offset):
        return unpack_from('<f', self.raw_data, offset)[0]

    def read_vec3f(self, offset):
        return unpack_from('<3f', self.raw_data, offset)

    def read_vec4f(self, offset):
        return unpack_from('<4f', self.raw_data, offset)

    def get_ref(self, field_offset):
        """Get the IGZObject referenced at a field offset, or None."""
        ref = self.references.get(field_offset)
        if isinstance(ref, IGZObject):
            return ref
        return None

    def get_raw_ref(self, field_offset):
        """Get raw reference value (IGZObject or global offset int), or None."""
        return self.references.get(field_offset)

    def __repr__(self):
        name = f' "{self.object_name}"' if self.object_name else ''
        return f'<IGZObject {self.type_name}{name} @0x{self.global_offset:X} ({self.type_size}B)>'


@dataclass(slots=True)
class FixupData:
    """Container for all parsed fixup tables."""
    tstr: list
    tmet: list
    mtsz: list
    rvtb: list    # encoded offsets (not resolved to global)
    rofs: list    # global offsets of pointer fields
    rstt: list    # global offsets of string fields
    root: list    # encoded offsets
    onam: list    # encoded offsets
    rnex: list    # global offsets of external named refs
    rext: list    # global offsets of external hashed refs
    rhnd: list    # global offsets of handle refs
    exnm: list    # list of (obj_hash, file_hash) tuples
    exid: list    # list of (obj_hash, file_hash) tuples
    rofs_set: set
    rstt_set: set
    rnex_set: set
    rext_set: set
    rhnd_set: set

class IgPlatform(Enum): # V5 unknown, but should be same as v6
    IG_CORE_PLATFORM_DEFAULT = 0x00, False
    IG_CORE_PLATFORM_WIN32   = 0x01, False
    IG_CORE_PLATFORM_WII     = 0x02, False
    IG_CORE_PLATFORM_DURANGO = 0x03, True  # v6: DEPRECATED (?)
    IG_CORE_PLATFORM_ASPEN   = 0x04, False
    IG_CORE_PLATFORM_XENON   = 0x05, False
    IG_CORE_PLATFORM_PS3     = 0x06, False # v10: LE and 64bit (Win64?) > this is from a mod file, though
    IG_CORE_PLATFORM_OSX     = 0x07, False
    IG_CORE_PLATFORM_WIN64   = 0x08, True
    IG_CORE_PLATFORM_CAFE    = 0x09, False
    IG_CORE_PLATFORM_RASPI   = 0X0A, False # v6: NGP = True
    IG_CORE_PLATFORM_ANDROID = 0X0B, False
    IG_CORE_PLATFORM_ASPEN64 = 0X0C, True  # v6-8: MARMALADE = False (DEPRECATED in Trap Team v8)
    IG_CORE_PLATFORM_LGTV    = 0X0D, False # v6: Unused
    IG_CORE_PLATFORM_PS4     = 0X0E, True  # v6: Unused
    IG_CORE_PLATFORM_WP8     = 0X0F, False # v6: Unused
    IG_CORE_PLATFORM_LINUX   = 0X10, False # v6: Unused
    IG_CORE_PLATFORM_MAX     = 0xFF, False
    def __new__(cls, value: int, is64bit: bool):
        member = object.__new__(cls)
        member._value_ = value
        member._is64bit = is64bit
        return member
    @classmethod
    def _missing_(cls, value: int):
        member = cls.IG_CORE_PLATFORM_MAX
        member._value_ = value
        return member
    def is64bit(member, version: int) -> bool:
        return (True if version == 6 and member._value_ == 0X0A else
                False if version in (6, 7, 8) and member._value_ == 0X0C else
                member._is64bit)

INCOMPATIBLE_PLATFORMS = (0x03, 0X0D, 0X0E, 0X0F, 0X10)
#{
#    6: (0x03, 0X0D, 0X0E, 0X0F, 0X10)
#    #8: (0X0C)
#}

@dataclass(slots=True)
class IgzBuffer:
    '''Describes a section in the IGZ file.'''
    Offset: int
    Size: int
    Alignment: int
    ID: int
    Name: str = None
    Data: bytes = None
    #def Slice(self, size: int) -> bytes:
    #    return self.Data[self.Offset:self.Offset + size]

@dataclass
class IgzHeader:
    Magic: int
    Version: int
    TypeHash: int # On v6 or less, this is unknown (sub-version?)
    Platform: int
    FixupCount: int
    @property
    def is64bit(self) -> bool:
        v = 6 if self.Version == 5 else self.Version
        if v == 6: assert(self.Platform not in INCOMPATIBLE_PLATFORMS)
        return IgPlatform(self.Platform).is64bit(self.Version)

@dataclass(slots=True)
class FixupHeader:
    Magic: int
    Count: int
    Length: int
    DataOffset: int

class IgzFixup(Enum):
    EXID = 0x44495845 # table 2xCount hashes
    EXNM = 0x4D4E5845 # size+offset list (3264) (uneven name, even material ref)
    MTSZ = 0x5A53544D # metatype sizes
    NSPC = 0X4350534E # encoded offsets?
    ONAM = 0x4D414E4F # offset to igNameList for sceneinfo root nodes
    REXT = 0x54584552 # encoded offsets
    RHND = 0x444E4852 # encoded offsets
    RNEX = 0x58454E52 # encoded offsets?
    ROOT = 0x544F4F52 # offset(s) to hierarchy root node(s)
    ROFS = 0x53464F52 # encoded offsets
    RPID = 0x44495052 # encoded offsets
    RSTT = 0x54545352 # encoded offsets (uint at offset are index in TSTR)
    RVTB = 0x42545652 # encoded offsets (of all nodes?)
    TDEP = 0x50454454
    TMET = 0x54454D54
    TMHN = 0x4E484D54 # texture buffer?
    TSTR = 0x52545354

FIXUP_MAP_V6 = (
    IgzFixup.TMET,
    IgzFixup.TSTR,
    IgzFixup.EXID,
    None, #IgzFixup.EXNM,
    None, #IgzFixup.RSTT, # encoded
    None, #IgzFixup.RVTB, # 5+6 maybe mixed up (both encoded)
    None, #IgzFixup.ROFS, #
    None, #IgzFixup.REXT,
    IgzFixup.ROOT,
    None, # ONAM p1: offset(s) to igHandleList for sceneinfo root nodes
    IgzFixup.TMHN,
    IgzFixup.TMHN, # EXNM but embedded
    None, #IgzFixup.RHND,
    IgzFixup.MTSZ,
    None, # ONAM p2: offset(s) to igStringRefList for sceneinfo root nodes (or NSPC?)
    None, #IgzFixup.TDEP,
    None, #IgzFixup.RPID,
    None  #IgzFixup.RNEX,
)

IGZ_HEADER_STRUCT = '5I4x' # v7+


# --- Nibble decoder ---

def decompress_offsets(data: bytes, old_version_v6: bool) -> list:
    '''Decode a delta-encoded nibble stream into a sorted list of offsets.

    Each nibble (4 bits) has:
      - Bits 0-2 (0x7): 3 data bits
      - Bit 3    (0x8): continuation flag (1=continue, 0=complete this value)

    Values accumulate via shifting, then:
      - v6:  result = previous + value * 4 + 4
      - v10: result = previous + value * 4

    Notes:
      - Any code deduplication would make it slower
      - Any generator or sized list solution would make it slightly slower
      - The extra buffer for data (to avoid checking for offsets) makes it slightly slower
      - Using jit compiling (e.g. Numba) would make this faster
    '''
    value: int = 0
    current_value: int = 0
    current_shift: int = 0
    add = 4 if old_version_v6 else 0 # or (self.version < 9)
    result = []

    for byte in data:
        # low nibble
        current_value |= (byte & 0x7) << current_shift
        current_shift += 3
        if not (byte & 0x8): # Continuation bit is 0
            value += current_value * 4 + add
            result.append(value)
            current_value = 0
            current_shift = 0
        # high nibble
        current_value |= ((byte >> 4) & 0x7) << current_shift
        current_shift += 3
        if not (byte & 0x80): # Continuation bit is 0
            value += current_value * 4 + add
            result.append(value)
            current_value = 0
            current_shift = 0

    return result

def _decode_nibbles(data, offset, count, add_one=True):
    """Decode a delta-encoded nibble stream into a sorted list of offsets.

    Each nibble (4 bits) has:
      - Bit 3 (0x8): continuation flag (1=continue, 0=complete this value)
      - Bits 0-2 (0x7): 3 data bits

    Values accumulate via shifting, then:
      - v6: result = previous + (value + 1) * 4  (add_one=True)
      - v10: result = previous + value * 4        (add_one=False)
    """
    result = []
    pos = offset
    current_value = 0
    current_shift = 0

    while len(result) < count:
        if pos >= len(data):
            break
        byte = data[pos]
        pos += 1

        for nibble_idx in range(2):
            nibble = (byte >> (nibble_idx * 4)) & 0xF
            data_bits = nibble & 0x7
            continuation = nibble & 0x8

            current_value |= (data_bits << current_shift)
            current_shift += 3

            if continuation == 0:
                last = result[-1] if result else 0
                if add_one:
                    result.append(last + (current_value + 1) * 4)
                else:
                    result.append(last + current_value * 4)

                if len(result) >= count:
                    break

                current_value = 0
                current_shift = 0

    return result


# --- IGZ Reader ---

class IgzReader:
    buffers: list[IgzBuffer]

    def __init__(self, filepath: Path):
        #self.filepath = filepath
        with filepath.open('rb') as f: # buffering=0x100000
            # throws key error, if magic is wrong
            hd = f.read(24)
            self._endian_sign: str = {0x015A4749: '>', 0x49475A01: '<'}[unpack_from('<I', hd)[0]]
            self.header: IgzHeader = IgzHeader(0x49475A01, *unpack_from(self._endian_sign + '4I4x', hd, 4))
            old_version_v6 = self.header.Version < 0x07
            if old_version_v6: f.seek(0x10)
            fixups, *self.buffers = self._read_buffers(f)

        if old_version_v6:
            self.header.Platform, \
            self.header.FixupCount = unpack_from(self._endian_sign + 'H6xI', fixups.Data, 8) # should probably be 7I (offset 0)

        self._pointer_shift: int = 0x18 if old_version_v6 else 0x1B
        self._pointer_mask: int = 0x00FFFFFF if old_version_v6 else 0x07FFFFFF
        self.is64bit: bool = self.header.is64bit
        self._uint3264: str = 'Q' if self.is64bit else 'I'
        self._uint3264_str: Struct = Struct(self._endian_sign + self._uint3264)
        self._ushort_str: Struct = Struct(self._endian_sign + 'H')
        self._uint32_str: Struct = Struct(self._endian_sign + 'I')
        # Some code builds on the assumption that all 64bit platforms are LE (memory ref)
        assert not self.is64bit or self._endian_sign == '<'

        self.ROOT: tuple[int] = tuple()
        self._fixups: dict[IgzFixup, Any] = {}
        self._parse_fixups(fixups.Data, f"{self._endian_sign}{'I8x3I' if old_version_v6 else '4I'}", old_version_v6)
        self.TMET: list[str] = self._fixups[IgzFixup.TMET]
        self.TSTR: list[str] = self._fixups[IgzFixup.TSTR]
        self.TMHN: np.ndarray = self._fixups.get(IgzFixup.TMHN)

        self.arkRegisteredTypes = build_registry(self.is64bit, self._endian_sign)
        self.NAMV6 = [self.processNode(p) for p in self._fixups.get(0x0E, range(0))]

    def read(self, _struct: str, _pointer: int) -> tuple:
        buf = self._get_buffer(_pointer)
        return unpack_from(self._endian_sign + _struct, buf.Data, buf.Offset)

    def readStruct(self, _struct: Struct, _pointer: int) -> tuple:
        buf = self._get_buffer(_pointer)
        return _struct.unpack_from(buf.Data, buf.Offset)

    def readString(self, index: int) -> str:
        # WIP: Need to handle unnamed (negative?)
        if index < len(self.TSTR):
            return self.TSTR[index]
        else: # assume index=pointer
            buf = self._get_buffer(index)
            return buf.Data[buf.Offset:buf.Data.index(b'\x00', buf.Offset)].decode('ascii', errors='replace')

    def readStringTable(self, data: bytes) -> list:
        '''
        Decode a bytes string in ASCII and returns all strings delimited by 0 bytes as a list.
        (Note: most efficient, but gets slow, if the data has lots of 0 bytes and few others.)
        '''
        return list(filter(None, data.decode('ascii', errors='replace').split('\x00')))

    def readMemoryRef(self, pointer: int) -> IgzBuffer:
        assert pointer != 0
        return self._get_buffer(pointer)

    def readMemorySlice(self, pointer: int, size: int) -> bytes:
        # WIP: Remove?
        assert pointer != 0
        if pointer & 0x80000000: # unconfirmed
            raise IndexError(f'Buffer index of pointer 0x{pointer:08X} is out of range.')
        buf = self.buffers[pointer >> self._pointer_shift]
        offset = pointer & self._pointer_mask
        return buf.Data[offset:offset + size]

    def readIntVector(self, count: int, pointer: int) -> tuple[int]:
        return self.read(f'{count}i', pointer)

    def readPointerVector(self, count: int, pointer: int) -> tuple[int]:
        return self.readStruct(Struct(self.Fmt3264(count)), pointer)

    def readUShort(self, pointer: int) -> int:
        return self.readStruct(self._ushort_str, pointer)[0]

    def readUInt3264(self, pointer: int) -> int:
        return self.readStruct(self._uint3264_str, pointer)[0]

    def Fmt3264(self, count: int) -> tuple:
        return f'{self._endian_sign}{count}{self._uint3264}'

    def processNode(self, pointer: int) -> Any:
        buf = self._get_buffer(pointer)
        _type_index, = self._uint3264_str.unpack_from(buf.Data, buf.Offset)
        #_type_index = self.readUInt3264(pointer)

        try:
            metatype = self.TMET[_type_index]
            #if metatype.endswith("Buffer"): pass
            #elif metatype.endswith("List"): pass
            #else:
            #    _id = bs.readUInt64() if self.is64Bit else bs.readUInt()
            #    isAttribute = _id >> 0x10 == 0xFFFF
            #    name = _id & 0xFFFF if isAttribute else self.stringList[_id]
            igObj, _struct = self.arkRegisteredTypes[metatype]
            #print(f'Processing @0x{pointer:08X}: {metatype}')
            return igObj(self, *_struct.unpack_from(buf.Data, buf.Offset)) # WIP: don't pass self to attributes?
        except IndexError:
            print(f'Skipping   @0x{pointer:08X}: Got typeIndex: 0x{_type_index:08X}')
        except KeyError:
            szs = self._fixups.get(IgzFixup.MTSZ, [])
            print(f'Skipping   @0x{pointer:08X}: {metatype} not implemented (size {szs[_type_index] if _type_index < len(szs) else 0})')

        return None

    def parseHierarchy(self) -> Iterator:
        for p in self.ROOT:
            yield self.processNode(p)

    def _read_buffers(self, f: BinaryIO):
        '''Memory Pool Table:
        Parse the pointer table (IgzBuffer, 16 bytes each), starting at offset 0x10,
        buffer and the name strings of the pointers (currently removed/commented).
        '''
        if self.header.Version < 0x07: f.seek(0x10)
        buffers = []
        for i in range(0x20): # 0x20 should be a safe limit
            b = IgzBuffer(*unpack_from('4I', f.read(16)))
            if b.Offset == 0:
                break
            #print(f'section {i}: offset 0x{b.Offset:08X}')
            buffers.append(b)

        #buffer_names = self.readStringTable(f.read((pointers[0].Offset - f.tell())).strip(b'\x00'))
        for b in buffers: #for i, b in enumerate(buffers)
            f.seek(b.Offset) # first always 0x800 ?
            b.Data = f.read(b.Size)
            # b.Alignment?
            #if i != 0:
            #    b.Name = buffer_names[i-1]

        # We're expecting exceptions if the strings don't match.
        # It's possible that we need a safer approach with a fallback.

        return buffers

    def _parse_fixups(self, data: bytes, fixup_header_struct: str, old_version_v6: bool):
        '''
        Fixup Tables:
        Parse the information at the first pointer.

        v6 format: 0x28-byte inner header, then 14 fixup blocks in fixed order.
        Each block: count(4) + totalSize(4) + unused(4) + data.
        '''
        offset = 0x1C if old_version_v6 else 0

        for i in range(self.header.FixupCount):
            h = FixupHeader(*unpack_from(fixup_header_struct, data, offset))
            offset_next = offset + h.Length
            offset += h.DataOffset
            #length = self.Length - self.DataOffset
            magic = FIXUP_MAP_V6[h.Magic] if old_version_v6 else IgzFixup(h.Magic)
            assert magic not in self._fixups, f'Duplicate section found for {magic}'

            if magic in (IgzFixup.TMET, IgzFixup.TSTR):
                self._fixups[magic] = self.readStringTable(data[offset:offset_next])[:h.Count]
                #for j in range(h.Count): print(f'metatypes[0x{j:02X}]: {self._fixups[magic][j]}')
            elif magic == IgzFixup.MTSZ:
                # assert h.Count * 4 == length
                self._fixups[magic] = unpack_from(f'{self._endian_sign}{h.Count}I', data, offset)
            elif magic == IgzFixup.TMHN: # WIP
                # assert h.Count * 4 * self._uint3264_str.size == length
                self._fixups[magic] = np.frombuffer(data,
                    dtype  = self._uint3264_str,
                    count  = h.Count * 2,
                    offset = offset).reshape(h.Count, 2)
                #for sz, o in self._fixups[magic]:
                #    self._f.seek(_get_global_offset(o))
                #    memory = self._f.read(sz & 0xFFFFFF) # 0xFF000000 seems important
            elif magic in (IgzFixup.EXID, IgzFixup.EXNM):
                # assert h.Count * 8 == length
                self._fixups[magic] = np.frombuffer(data,
                    dtype  = f'{self._endian_sign}u4',
                    count  = h.Count * 2,
                    offset = offset).reshape(h.Count, 2)
                # IGZ_IMG_FORMAT.get(self._fixups[magic][-1,0])
            elif magic == IgzFixup.ROOT: # and/or RNEX, REXT, ONAM, RHND, NSPC?
                self.ROOT = unpack_from(f'{self._endian_sign}{h.Count}I', data, offset)
            elif magic in (IgzFixup.RVTB, IgzFixup.RSTT, IgzFixup.ROFS, IgzFixup.REXT, IgzFixup.RHND, IgzFixup.ONAM): # ROOT??, REXT?, RNEX?, NSPC, RPID
                self._fixups[magic] = decompress_offsets(data[offset:offset_next], old_version_v6)
                # assert len(offsets) == h.Count
                #IgzFixup.RSTT: count * 'B' + '4BI'?
                #IgzFixup.RVTB: count * 'B' + '3B'?
                #IgzFixup.ONAM: count * 'I'? > always last?
                #4/6/7: count * 'B' (also 5), length * 'B'
                #12: count / 10 * 16 * 'B', length * 'B'
                #16: (count + 2) * 2 * 'B'
            elif magic == IgzFixup.TDEP:
                self._fixups[magic] = self.readStringTable(data[offset:offset_next])[:h.Count * 2]
                #in self.header.Version == 0x09, strings are aligned to 2 bytes (or 2 byte encoding, like unicode)
            elif h.Magic == 0x0E:
                self._fixups[h.Magic] = unpack_from(f'{self._endian_sign}{h.Count}I', data, offset)

            offset = offset_next

        #for _type, _size in list(zip(self._fixups[IgzFixup.TMET], self._fixups[IgzFixup.MTSZ]))

    def _get_buffer(self, pointer: int) -> tuple[IgzBuffer, int]:
        if pointer & 0x80000000: # unconfirmed
            raise IndexError(f'Buffer index of pointer 0x{pointer:08X} is out of range.')
        buf = self.buffers[pointer >> self._pointer_shift]
        buf.Offset = pointer & self._pointer_mask
        return buf

class IGZReaderAI:
    """Reads and parses an IGZ format file."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.data = None
        self.version = 0
        self.platform = 0
        self.chunks = []
        self.pool_names = []
        self.fixups = FixupData()
        self.objects = {}       # global_offset -> IGZObject
        self.objects_by_type = {}  # type_name -> [IGZObject]

    def read(self):
        """Read and parse the entire IGZ file."""
        with open(self.filepath, 'rb') as f:
            self.data = f.read()

        self._parse_header()
        self._parse_chunk_table()
        self._parse_pool_names()
        self._parse_fixups()
        self._instantiate_objects()
        self._resolve_references()
        self._resolve_names()

    def _parse_header(self):
        """Parse the 16-byte IGZ header (magic, version, platform, unused)."""
        if len(self.data) < 16:
            raise ValueError(f"File too small for IGZ header: {len(self.data)} bytes")

        magic = unpack_from('<I', self.data, 0)[0]
        if magic != IGZ_MAGIC:
            raise ValueError(
                f"Invalid IGZ magic: 0x{magic:08X} (expected 0x{IGZ_MAGIC:08X})")

        self.version = unpack_from('<I', self.data, 4)[0]
        self.platform = unpack_from('<I', self.data, 8)[0]

    def _parse_chunk_table(self):
        """Parse the ChunkInfo table (16 bytes each: offset, size, alignment, id)."""
        pos = 0x10  # After 16-byte header

        while pos + 16 <= len(self.data):
            off, size, align, ident = unpack_from('<4I', self.data, pos)

            if off == 0:
                break

            chunk = ChunkInfo(off, size, align, ident)
            self.chunks.append(chunk)
            pos += 16

    def _parse_pool_names(self):
        """Parse memory pool name strings between chunk table and first section."""
        if not self.chunks:
            return

        # Find the padding area between chunk table end and first section
        chunk_table_end = 0x10 + len(self.chunks) * 16 + 16
        first_section = self.chunks[0].offset

        # Scan for the first non-zero byte
        name_start = None
        for i in range(chunk_table_end, min(first_section, len(self.data))):
            if self.data[i] != 0:
                name_start = i
                break

        if name_start is None:
            return

        # Read null-terminated strings, one per unique chunk identifier
        pos = name_start
        seen_ids = set()
        for chunk in self.chunks:
            if chunk.identifier in seen_ids:
                for prev in self.chunks:
                    if prev.identifier == chunk.identifier and prev.name:
                        chunk.name = prev.name
                        break
                continue

            seen_ids.add(chunk.identifier)

            if pos >= first_section:
                break

            try:
                end = self.data.index(0, pos)
            except ValueError:
                break
            name = self.data[pos:end].decode('ascii', errors='replace')
            chunk.name = name
            self.pool_names.append(name)
            pos = end + 1

    def _parse_fixups(self):
        """Parse the fixup section (section 0).

        v6 format: 0x28-byte inner header, then 14 fixup blocks in fixed order.
        Each block: count(4) + totalSize(4) + unused(4) + data.
        """
        if not self.chunks:
            return

        fixup_chunk = self.chunks[0]
        base = fixup_chunk.offset

        # Validate inner magic
        inner_magic = unpack_from('<I', self.data, base)[0]
        if inner_magic != IGZ_MAGIC:
            raise ValueError("Fixup section inner header has wrong magic")

        # Read number of fixup blocks from inner header
        num_fixup_blocks = unpack_from('<I', self.data, base + 0x10)[0]

        # Fixup blocks start after the inner header
        pos = base + V6_FIXUP_INNER_HEADER_SIZE

        add_one = (self.version <= 8)  # v6 uses +1, v10 doesn't

        for block_idx in range(num_fixup_blocks):
            if pos + 12 > len(self.data):
                break

            count, total_size, _ = unpack_from('<III', self.data, pos)
            data_start = pos + 12
            data_end = pos + total_size

            if block_idx < len(V6_FIXUP_ORDER):
                fixup_name = V6_FIXUP_ORDER[block_idx]
                self._parse_fixup_block(fixup_name, count, data_start, data_end,
                                        add_one)

            pos += total_size

    def _parse_fixup_block(self, name, count, data_start, data_end, add_one):
        """Parse a single fixup block by type name."""
        if name == 'TSTR':
            self._parse_string_table(self.fixups.tstr, data_start, data_end, count)
        elif name == 'TMET':
            self._parse_string_table(self.fixups.tmet, data_start, data_end, count)
        elif name == 'MTSZ':
            self._parse_mtsz(data_start, count)
        elif name == 'EXNM':
            self._parse_hash_pairs(self.fixups.exnm, data_start, count)
        elif name == 'EXID':
            self._parse_hash_pairs(self.fixups.exid, data_start, count)
        elif name in ('RVTB', 'RSTT', 'ROFS', 'RPID', 'REXT', 'RHND',
                       'ROOT', 'ONAM', 'NSPC'):
            self._parse_r_fixup(name, data_start, count, add_one)

    def _parse_string_table(self, target_list, start, end, count):
        """Parse null-terminated strings with optional padding byte between entries."""
        pos = start
        for _ in range(count):
            if pos >= end:
                break
            try:
                null_pos = self.data.index(0, pos, end)
            except ValueError:
                null_pos = end
            s = self.data[pos:null_pos].decode('ascii', errors='replace')
            target_list.append(s)
            pos = null_pos + 1
            # Skip padding null (same as Crash NST: if PeekChar() == '\0', read it)
            if pos < end and self.data[pos] == 0:
                pos += 1

    def _parse_mtsz(self, start, count):
        """Parse MTSZ (type sizes) - array of uint32."""
        for i in range(count):
            size = unpack_from('<I', self.data, start + i * 4)[0]
            self.fixups.mtsz.append(size)

    def _parse_hash_pairs(self, target_list, start, count):
        """Parse pairs of uint32 hashes (EXNM or EXID format)."""
        for i in range(count):
            h1 = unpack_from('<I', self.data, start + i * 8)[0]
            h2 = unpack_from('<I', self.data, start + i * 8 + 4)[0]
            target_list.append((h1, h2))

    def _parse_r_fixup(self, name, data_start, count, add_one):
        """Parse an R-type fixup (nibble-encoded offset list)."""
        offsets = _decode_nibbles(self.data, data_start, count, add_one)

        if name == 'RVTB':
            self.fixups.rvtb = offsets
        elif name == 'ROFS':
            self.fixups.rofs = [self._get_global_offset(o) for o in offsets]
            self.fixups.rofs_set = set(self.fixups.rofs)
        elif name == 'RSTT':
            self.fixups.rstt = [self._get_global_offset(o) for o in offsets]
            self.fixups.rstt_set = set(self.fixups.rstt)
        elif name == 'ROOT':
            self.fixups.root = offsets
        elif name == 'ONAM':
            self.fixups.onam = offsets
        elif name == 'RNEX':
            self.fixups.rnex = [self._get_global_offset(o) for o in offsets]
            self.fixups.rnex_set = set(self.fixups.rnex)
        elif name == 'REXT':
            self.fixups.rext = [self._get_global_offset(o) for o in offsets]
            self.fixups.rext_set = set(self.fixups.rext)
        elif name == 'RHND':
            self.fixups.rhnd = [self._get_global_offset(o) for o in offsets]
            self.fixups.rhnd_set = set(self.fixups.rhnd)

    def _get_global_offset(self, encoded_offset):
        """Convert an encoded offset to a global file offset.

        If value <= 0x7FFFFFF: offset relative to chunk[1] (first data section).
        Otherwise: high 5 bits = chunk_index - 1, low 27 bits = local offset.
        """
        if len(self.chunks) < 2:
            return encoded_offset

        if encoded_offset <= 0x7FFFFFF:
            return self.chunks[1].offset + encoded_offset
        else:
            chunk_index = (encoded_offset >> 0x1B) + 1
            local_offset = encoded_offset & 0x7FFFFFF
            if chunk_index < len(self.chunks):
                return self.chunks[chunk_index].offset + local_offset
            return encoded_offset

    def _instantiate_objects(self):
        """Create IGZObject instances from RVTB entries."""
        if not self.fixups.rvtb or not self.fixups.tmet or not self.fixups.mtsz:
            return

        for encoded_offset in self.fixups.rvtb:
            global_offset = self._get_global_offset(encoded_offset)

            if global_offset + 4 > len(self.data):
                continue

            type_index = unpack_from('<I', self.data, global_offset)[0]

            if type_index >= len(self.fixups.tmet):
                continue

            type_name = self.fixups.tmet[type_index]
            type_size = (self.fixups.mtsz[type_index]
                         if type_index < len(self.fixups.mtsz) else 0)

            obj = IGZObject(type_name, type_index, type_size, global_offset)

            if type_size > 0 and global_offset + type_size <= len(self.data):
                obj.raw_data = self.data[global_offset:global_offset + type_size]

            self.objects[global_offset] = obj

            if type_name not in self.objects_by_type:
                self.objects_by_type[type_name] = []
            self.objects_by_type[type_name].append(obj)

    def _resolve_references(self):
        """
        Use ROFS to resolve pointer fields within objects to target objects.
        
        Note by ak2yny: It's unclear what this actually does and why.
                        I think it's better to keep the tree structure nodes.
        """
        if not self.fixups.rofs_set:
            return

        # Build interval map for fast object lookup
        obj_intervals = []
        for obj in self.objects.values():
            obj_intervals.append((obj.global_offset, obj.global_offset + obj.type_size, obj))
        obj_intervals.sort()

        # For each ROFS offset, find the containing object and resolve the pointer
        for rofs_global in self.fixups.rofs:
            # Binary search for containing object
            # Note by ak2yny: This is bad code, because we're looking for the object that matches the ROFS offset, not the one that is closest.
            owner = None
            lo, hi = 0, len(obj_intervals) - 1
            while lo <= hi:
                mid = (lo + hi) // 2
                start, end, obj = obj_intervals[mid]
                if rofs_global < start:
                    hi = mid - 1
                elif rofs_global >= end:
                    lo = mid + 1
                else:
                    owner = obj
                    break

            if owner is None:
                continue

            field_offset = rofs_global - owner.global_offset
            if field_offset + 4 > owner.type_size:
                continue

            # Read the encoded pointer value (use lower 32 bits)
            ptr_value = unpack_from('<I', owner.raw_data, field_offset)[0]

            # Decode to global offset
            target_global = self._get_global_offset(ptr_value)
            target_obj = self.objects.get(target_global)
            if target_obj is not None:
                owner.references[field_offset] = target_obj
            else:
                # Raw data pointer (vertex buffer, index buffer, etc.)
                owner.references[field_offset] = target_global

    def _resolve_names(self):
        """Resolve object names from ROOT/ONAM fixups and RSTT string refs."""
        # Build a map of global_offset -> (obj, field_offset, tstr_string) for RSTT
        # Use a dict keyed by object global offset for string refs
        # NOTE by ak2yny: Some of the worst code I've ever seen.
        #                 Goes back and forth between heavy Py objects for no reason.
        string_refs_by_obj = {}  # obj_global_offset -> {field_offset: string}

        if self.fixups.rstt_set and self.fixups.tstr:
            for rstt_global in self.fixups.rstt:
                for obj in self.objects.values():
                    if obj.global_offset <= rstt_global < obj.global_offset + obj.type_size:
                        field_offset = rstt_global - obj.global_offset
                        if field_offset + 4 <= obj.type_size:
                            tstr_index = unpack_from('<I', obj.raw_data, field_offset)[0]
                            if tstr_index < len(self.fixups.tstr):
                                if obj.global_offset not in string_refs_by_obj:
                                    string_refs_by_obj[obj.global_offset] = {}
                                string_refs_by_obj[obj.global_offset][field_offset] = \
                                    self.fixups.tstr[tstr_index]
                        break

        self._string_refs_by_obj = string_refs_by_obj

        # Try to resolve object names from ROOT/ONAM
        if self.fixups.root and self.fixups.onam:
            root_global = self._get_global_offset(self.fixups.root[0])
            onam_global = self._get_global_offset(self.fixups.onam[0])

            root_obj = self.objects.get(root_global)
            onam_obj = self.objects.get(onam_global)

            if root_obj is not None and onam_obj is not None:
                self._resolve_list_names(root_obj, onam_obj)

    def _resolve_list_names(self, root_obj, name_obj):
        """Match igObjectList entries to igNameList entries."""
        # Collect object refs from root_obj
        obj_refs = []
        for fo in sorted(root_obj.references.keys()):
            ref = root_obj.references[fo]
            if isinstance(ref, IGZObject):
                obj_refs.append(ref)

        # Collect name strings from name_obj via RSTT
        name_strings = []
        name_str_refs = self._string_refs_by_obj.get(name_obj.global_offset, {})
        for fo in sorted(name_str_refs.keys()):
            name_strings.append(name_str_refs[fo])

        for i, obj in enumerate(obj_refs):
            if i < len(name_strings):
                obj.object_name = name_strings[i]

    def get_objects_by_type(self, type_name):
        """Get all objects of a given type name."""
        return self.objects_by_type.get(type_name, [])

    def get_data_at(self, global_offset, size):
        """Read raw bytes from the file at a global offset."""
        if global_offset + size <= len(self.data):
            return self.data[global_offset:global_offset + size]
        return None

    def get_section_data(self, section_name):
        """Get the raw data for a named section."""
        for chunk in self.chunks:
            if chunk.name == section_name:
                return self.data[chunk.offset:chunk.offset + chunk.size]
        return None

    def get_section_offset(self, section_name):
        """Get the file offset of a named section."""
        for chunk in self.chunks:
            if chunk.name == section_name:
                return chunk.offset
        return None
