# MUA2 PAK file extractor for sounds (extracts .fsb), should work for other IGA
# by ak2yny, based on MUA2 QuickBMS script by Luigi Auriemma & igArchiveExtractor by NefariousTechSupport
# https://aluigi.altervista.org/quickbms.htm
# https://github.com/NefariousTechSupport/igArchiveExtractor/tree/no-msbuild


import glob
from argparse import ArgumentParser
from dataclasses import dataclass, InitVar
from enum import Enum
from itertools import count
from pathlib import Path
from struct import pack, iter_unpack, Struct, unpack_from


IGA_ID_LE = b'IGA\x1a'
PAK_HEADER_STRUCT = (
    # '4s'
    '4I'
    '36s'
)
PAK_HEADER_SZ = 0x34
CHUNK_SIZE = 0x8000 # if header.version.value < 9 else 0x800000

# need more info about version
# BMS script differences:
# - VA0 possibly justified to 16x through:
#   if version < 0xB and version != 4 and names_offset < chunk_alignment
#   but reads names_offset from 0x1C first (then 0x2C as it should)
# - VB1 also 4xI12xI...
# - VC0 seemingly unhandled
# - V9+ handle 64bit files, using bitfields
#   bit_mod, offset, size, mode B3xI2I (IB3x2I depending on version or endian?)
#   offset = offset | (bit_mod << 40)
#   but could it be Q2I instead?
class PAK_Version(Enum):
    V4  = 0x00000004, 0x30, '3I',         '3I'    # MUA2 RE Steam Sounds (containing FSB); SkylandersSpyrosAdventureWii
    V8  = 0x00000008, 0x34, '4x3I',       '3I'    # SkylandersSpyrosAdventureWiiU / Giants
    V9  = 0x00000009, 0x38, '4xI16x2I',   '3I4x'  # ? (values not confirmed, last 4x possibly ID)
    VA0 = 0x0000000A, 0x38, '4xI16x2I',   '4x3I'  # SkylandersSwapForce
    VA1 = 0x1000000A, 0x38, '4xI12xI4xI', 'I4x2I' # SkylandersLostIslands
    VB0 = 0x0000000B, 0x38, '4xI12xI4xI', 'I4x2I' # SkylandersTrapTeam / SkylandersSuperChargers (?)
    VB1 = 0x1000000B, 0x38, '4xI16x2I',   '4x3I'  # SkylandersSuperChargers
    VB2 = 0x2000000B, 0x38, '4xI12xI4xI', 'I4x2I' # SkylandersImaginatorsPS4
    VC0 = 0x0000000C, 0x38, '4xI8xI4xI',  'I4x2I' # CrashNST
    def __new__(cls, value: int, crc_to: int, ndt: str, fdt: str):
        member = object.__new__(cls)
        member._value_ = value
        member.table_offset = crc_to
        member.names_dtype = ndt
        member.file_info_dtype = fdt
        return member

@dataclass
class PAK_Header:
    endian: str
    # iga_id: bytes
    version: int|PAK_Version
    table_size: int
    count: int
    chunk_alignment: int  # V4: N/A
    # ------  ^^ 0x04 - 0x14 ^^ ------
    _data: InitVar[bytes]
    # 0xFFFFFFFF // count # V4: 0x10
    slop: int = 0         # V4: 0x14 small number
    names_offset: int = 0 # V4: 0x18
    names_size: int = 0   # V4: 0x1C
    flags: int = 0        # V4: N/A
    file_info_size: int = 0
    file_info_dtype: None|Struct = None

    def __post_init__(self, _data):
        self.version = PAK_Version(self.version)
        self.file_info_size = self.table_size - self.count * 4
        self.file_info_dtype = Struct(self.endian + self.version.file_info_dtype)
        self.slop, self.names_offset, self.names_size = \
            unpack_from(self.endian + self.version.names_dtype, _data)
        if self.version == PAK_Version.V4:
            self.chunk_alignment = 0x0800 # fallback, should never be compressed
        else:
            self.flags, = unpack_from(self.endian + 'I', _data, self.version.table_offset - 0x18)
        # assert (0xFFFFFFFF // count) * count == 0xFFFFFFFF

    def check_size(self, file_size: int): # might not be important
        assert file_size <= 0xFFFFFFFF and file_size == self.names_offset + self.names_size and self.count * self.file_info_dtype.size == self.file_info_size

    #def write(self) -> bytes: # needs compatible class (prbly use inherit)
    #    return IGA_ID_LE if self.endian == '<' else IGA_ID_LE[::-1] + \
    #           pack(self.endian + '', self.version.value, *astuple(self)[2:])

def backup(output_file: Path):
    if not output_file.exists(): return
    for i in count(0):
        backup_file = output_file.with_stem(f'{output_file.stem}.backup{i}')
        if not backup_file.exists(): break
    output_file.rename(backup_file)

def _combine(input_folder: Path, output_file: Path):
    pass

def _extract(input_file: Path, output_folder: Path):
    with input_file.open('rb') as f:
        iga_id = f.read(4)
        e = '<' if iga_id == IGA_ID_LE else '>' if iga_id == IGA_ID_LE[::-1] else ''
        if not e:
            raise ValueError('File ID incorrect. Not a correct IGA file (.pak, .arc, .bld).')
        header = PAK_Header(e, *unpack_from(e + PAK_HEADER_STRUCT, f.read(PAK_HEADER_SZ)))
        header.check_size(input_file.stat().st_size)
        if header.names_offset:
            f.seek(header.names_offset)
            names = f.read(header.names_size)
            se = '<' if unpack_from('< I', names)[0] == header.count * 4 else '>' # not a good endian check
            file_names = (names[o:names.index(b'\x00', o)].decode() for o in unpack_from(f'{se} {header.count}I', names))
        backup(output_folder)
        f.seek(header.version.table_offset)
        _crc = f.read(header.count * 4)
        for o, s, m in header.file_info_dtype.iter_unpack(f.read(header.file_info_size)):
            f.seek(o)
            cm = m >> 24
            # files have chunk identifier header and need special handling of the compression
            if cm == 0x20 or (header.version == PAK_Version.V4 and cm == 0x10):
                # lzma_dynamic
                data = bytes()
                #while len(data) < s:
                #    
            elif cm in (0x00, 0x10):
                # deflate_noerror
                pass
            elif m == 0xFFFFFFFF:
                data = f.read(s)
            else:
                print(f'INFO: {file_path} is compressed. Decompression is not supported at this time.')
            file_path = Path(f'{o:08X}.bin' if not header.names_offset else
                             next(file_names) + '.fsb' if data[:3] == b'FSB' else
                             next(file_names))
            file_path = output_folder / (file_path.relative_to(f'{file_path.drive}\\')
                                         if file_path.is_absolute() else file_path)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(data)

def main():
    parser = ArgumentParser()
    parser.add_argument('input', help='input file (supports glob)')
    args = parser.parse_args()
    input_files = glob.glob(args.input.replace('[', '[[]'), recursive=True)

    if not input_files:
        raise ValueError('No files found')

    for input_file in input_files:
        input_file = Path(input_file)
        # assert input_file.suffix.casefold() == '.pak', 'The extension is wrong'

        if input_file.is_dir():
            _combine(input_file, Path(f'{input_file}.pak'))
        else:
            _extract(input_file, input_file.parent / input_file.stem)

if __name__ == '__main__':
    main()