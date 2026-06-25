'''
MUA2 Sound Bank Editor — Full GUI
===================================
Requires: Python 3.9+  +  customtkinter  (pip install customtkinter)

Features
--------
  • Load PAK + IGX together or separately
  • Tree view: Sounds (IGX) / FSB files (PAK)
  • Full FSB5 metadata: format, channels, sample rate, duration,
    loop points, num samples
  • Full IGX properties: looping, streaming, volume, pitch, channel
    group, 3D behaviour, fade in/out, ducking, play feature …
  • Search / filter
  • Extract single FSB or all FSBs
  • Replace FSB in-place (same slot)
  • Full repack (handles size changes, preserves header/TOC)
  • Hash calculator (FNV-1a)
  • System log with colour levels

Credits
--------
  • https://aluigi.altervista.org/quickbms.htm
  • https://github.com/gdawg/fsbext/blob/master/src/fsbext.c by aluigi
  • https://github.com/NefariousTechSupport/igArchiveExtractor/tree/no-msbuild
  • https://github.com/SamboyCoding/Fmod5Sharp/blob/master/Fmod5Sharp/FmodTypes/FmodSampleChunkType.cs
  • https://github.com/HearthSim/FSBReader
  • https://github.com/HearthSim/python-fsb5/blob/master/fsb5/__init__.py
  • https://qa.fmod.com/t/where-to-find-fev-file-header/12923/2
'''
# WIP: Add property editor (I think IGX only) or even IGX editor
#      Add platform config support (endian, etc.)
#      Add big endian support for fsb

import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from io import BytesIO
from json import dump, load
from pathlib import Path
from struct import pack, pack_into, iter_unpack, unpack_from
from subprocess import run
from threading import Thread
from tkinter import filedialog, messagebox, Listbox, StringVar
from tkinter.ttk import Style, Treeview
from customtkinter import *

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS / THEME
# ─────────────────────────────────────────────────────────────────────────────
set_appearance_mode('dark')
set_default_color_theme('blue')

# WIP: Modify the dark theme to be darker:
C_BG       = '#0d1117'
C_PANEL    = '#161b22'
#C_BORDER   = '#30363d'
C_ACCENT   = '#58a6ff'
C_GREEN    = '#3fb950'
C_YELLOW   = '#d29922'
C_RED      = '#f85149'
C_PURPLE   = '#bc8cff'
#C_ORANGE   = '#ffa657'
C_TEXT     = '#e6edf3' #light only
C_DIMTEXT  = '#8b949e'

# These don't support theming
COLOR_TAGS = (('dim', C_DIMTEXT), ('accent', C_ACCENT),
              ('green', C_GREEN), ('red', C_RED),
              ('warn', C_YELLOW), ('val', C_TEXT))
COLOR_TAGS_PROPERTY = COLOR_TAGS + (('accent2', C_PURPLE),)

FONT = 'Consolas' # Currently used for consoles and other UI

FSB5_FREQ_TABLE = (4000, 8000, 11000, 11025, 16000, 22050, 24000, 32000, 44100, 48000, 96000)
ID_IGA          = b'IGA\x1a'
ID_FSB5         = b'FSB5'
ID_IGA_BYENDIAN = {ID_IGA: '<', ID_IGA[::-1]: '>'}

FSBANKEXCL = Path(__file__).parent / 'fsbankexcl.exe' # from sys import executable

# ─────────────────────────────────────────────────────────────────────────────
# PAK / FSB5 CORE
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PAK_Entry:
    path: str
    _hash: int
    offset: int
    size: int
    compression: int
    # if self.compression == 0xFFFFFFFF: uncompressed
    # if self.compression >> 28 == 2 or PAK_Header_V4.version == 4 and self.compression >> 28 == 1: lzma_dynamic
    # if self.compression >> 28 in (0, 1): deflate_noerror

@dataclass
class PAK_Header_Base:
    version: int
    toc_size: int
    num_files: int

@dataclass
class PAK_Header_V4(PAK_Header_Base):
    hash_div: int # = 0xFFFFFFFF // num_files
    hash_slop: int # small number
    nt_offset: int
    nt_size: int
    entries: list[PAK_Entry] = field(default_factory=list)
    i2n: list[str] = field(default_factory=list)
    n2i: dict[str,int] = field(default_factory=dict)

@dataclass
class PAK_Header(PAK_Header_Base):
    alignment: int # instead of 0x0800
    hash_div: int
    hash_slop: int
    # unknown # V9+
    flags: int # V9+
    # 0 - 2 I unknown # V9+
    nt_offset: int
    # 0 - 1 I most likely nt related # V9+
    nt_size: int
    entries: list[PAK_Entry] = field(default_factory=list)

class PAK_Version(Enum):
    # MUA2 RE Steam Sounds: V4
    V4  = 0x00000004, 0x30, '4I',          '3I'    # SkylandersSpyrosAdventureWii
    V8  = 0x00000008, 0x34, '5I',          '3I'    # " WiiU / Giants
    V9  = 0x00000009, 0x38, '3I4xI8x2I',   '3I4x'  # ? (unconfirmed, last 4x = ID?)
    VA0 = 0x0000000A, 0x38, '3I4xI8x2I',   '4x3I'  # SkylandersSwapForce
    VA1 = 0x1000000A, 0x38, '3I4xI4xI4xI', 'I4x2I' # SkylandersLostIslands
    VB0 = 0x0000000B, 0x38, '3I4xI4xI4xI', 'I4x2I' # SkylandersTrapTeam / SSC (?)
    VB1 = 0x1000000B, 0x38, '3I4xI8x2I',   '4x3I'  # SkylandersSuperChargers (SSC)
    VB2 = 0x2000000B, 0x38, '3I4xI4xI4xI', 'I4x2I' # SkylandersImaginatorsPS4
    VC0 = 0x0000000C, 0x38, '3I4x2I4xI',   'I4x2I' # CrashNST
    def __new__(cls, value: int, toco: int, hdt: str, odt: str):
        member = object.__new__(cls)
        member._value_ = value
        member.toc_offset = toco
        member.toc_dtype = odt
        member.header2_dtype = hdt # from offset 0x10
        return member

class FSB_Format(Enum):
    NONE     = 0      # sample bitwidth
    PCM8     = auto() # 8
    PCM16    = auto() # 16
    PCM24    = auto() # 24
    PCM32    = auto() # 32
    PCMFloat = auto() # 32
    GCADPCM  = auto() # 14
    IMAADPCM = auto() # 4
    VAG      = auto() # 14
    HEVAG    = auto() # 16
    XMA      = auto() # 16
    MPEG     = auto() # 16
    CELT     = auto() # 
    AT9      = auto() # 16
    XWMA     = auto() # 
    Vorbis   = auto() # 16 or 24

#class FSB_ModeFlags(IntFlag):
#    NONE    = 0
#    Loop    = 1 << 16
#    EmbedFN = 2 << 16 # unconfirmed, could be Encode Sync Points

@dataclass
class FSB_Sound_Header:
    #index: int = 0
    name: str
    channels: int = 0
    frequency: int = 0
    samples: int = 0
    loop_start: int|None = None
    loop_end: int|None = None
    other_info: dict[int,bytes] = field(default_factory=dict)

@dataclass
class FSB_Header:
    version: int # extended version
    file_count: int
    samplehdr_size: int
    name_size: int
    audio_size: int # compressed sample data
    fmt: FSB_Format|int
    fmt_version: int
    _mode_flags: int # FSB_ModeFlags
    total_size: int = 0
    files: list[FSB_Sound_Header] = field(default_factory=list)
    def __post_init__(self):
        self.fmt = FSB_Format(self.fmt)
        self.total_size = (64 if self.version == 0 else 60) + self.samplehdr_size + self.name_size + self.audio_size

def fnv1a(text: str, basis: int = 0x811C9DC5) -> int:
    '''
    Fowler–Noll–Vo hash generator
    https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
    '''
    for c in text:
        basis = ((basis ^ ord(c)) * 0x1000193) & 0xFFFFFFFF
    return basis

def align_pak_entry(offset):
    return (offset + 0x07FF) & ~0x07FF #== -(-offset // 0x0800) * 0x0800

def read_string_table(data: bytes, count: int, end_offset: int) -> Iterator[str]:
    # we usually have only few items where enumerate + index would be more efficient, but only by a bit
    # https://stackoverflow.com/questions/33955800/which-is-more-pythonic-in-a-for-loop-zip-or-enumerate
    # Is the start table always LE?
    starts = unpack_from(f'<{count}I', data)
    ends = iter(starts)
    _ = next(ends)
    for start, end in zip(starts, ends):
        yield data[start:end - 1].decode('utf-8', 'replace')
    yield data[starts[-1]:end_offset - 1].decode('utf-8', 'replace')

def get_list_elements(list_element: ET.Element, root: ET.Element) -> Iterator[ET.Element]:
    for item in list_element.findall('listitem'):
        file, ref = item.get('ref').split('.')
        #assert file == root_name # should always be the case
        yield root.find(f'object[@refname="{ref}"]')


# ── FSB5 ──────────────────────────────────────────────────────────────────

def fsb5_parse(f: BytesIO, offset: int, pak: PAK_Header_V4) -> FSB_Header|None:
    # Note: the header requires at least 60 bytes
    f.seek(offset)
    if f.read(4) != ID_FSB5:
        pak.i2n.append(None)
        return None
    hdr = FSB_Header(*unpack_from('<8I', f.read(0x38)))
    if hdr.version == 0:
        _ = f.read(4)
    # uint64 compatibilityHash, deprecated
    # guid MD5 hash, based on header (seemingly without names and sample headers)

    if hdr.file_count == 0:
        pak.i2n.append(None)
        return hdr # or None
    # else assume 1 sample, for the sake of this app
    shdata = f.read(hdr.samplehdr_size)

    # Names
    name = '' if hdr.name_size < 5 else \
           (d := f.read(hdr.name_size))[4:d.index(b'\x00', 4)].decode('utf-8', 'replace')
    #assert hdr.name_size // 4 == hdr.file_count
    #names = read_string_table(data, hdr.file_count, offset=hdr.samplehdr_size, end_offset=hdr.name_size)
    pak.n2i[name.lower()] = len(pak.i2n)
    pak.i2n.append(name)

    #for i in range(file_count):
    sound = FSB_Sound_Header(name)
    bit_info, = unpack_from('<Q', shdata)
    has_chunk   = bit_info & 0b1
    freq_idx    = bit_info >> 1 & 0b1111
    sound.channels=(bit_info >> 5 & 0b1) + 1 # more than 2 are supplied below
    #assert bit_info >> 6 & 0x3FFFFFF == 0 # first data offset is always 0
    sound.samples = bit_info >> 34
    if freq_idx < 11:
        sound.frequency = FSB5_FREQ_TABLE[freq_idx]
    pos = 8
    while has_chunk and pos + 4 <= hdr.samplehdr_size:
        bit_info,  = unpack_from('<I', shdata, pos)
        has_chunk  = bit_info & 0b1
        chunk_size = bit_info >> 1 & 0xFFFFFF
        chunk_type = bit_info >> 25
        pos += 4
        #if chunk_type == 15: # OPUSDATALEN
        #if chunk_type == 14: # VORBISINTRALAYERS
        #if chunk_type == 13: # PEAKVOLUME
        #if chunk_type == 11: # VORBISDATA, crc32 uint32 + unknown
        #if chunk_type == 10: # XWMADATA
        #if chunk_type == 9: # ATRAC9CFG
        #if chunk_type == 8: # unused?
        #if chunk_type == 7: # DSPCOEFF
        #if chunk_type == 6: # XMASEEK
        #if chunk_type == 5: # comment (ints?) in MUA2, seemingly loop points
        #if chunk_type == 4: # comment (strings?)
        if chunk_type == 3 and chunk_size >= 8:
            sound.loop_start, sound.loop_end = unpack_from('<2I', shdata, pos)
        elif chunk_type == 2 and chunk_size >= 4:
            sound.frequency, = unpack_from('<I', shdata, pos)
        elif chunk_type == 1: # second B might be interleave size
            sound.channels, *_ = unpack_from(f'<{chunk_size}B', shdata, pos)
        else:
            sound.other_info[chunk_type] = shdata[pos:pos+chunk_size]
        pos += chunk_size

    hdr.files.append(sound)

    return hdr


# ── PAK ───────────────────────────────────────────────────────────────────

def pak_repack(original_path: Path, out: BytesIO, fsb_p: Path, pak: PAK_Header_V4):
    entries = list(fsb_p.glob('**/*.fsb'))
    new_count = len(entries)
    if not new_count: return []
    if new_count != pak.num_files:
        pak.num_files = new_count
        pak.toc_size = 16 * new_count
    pak.i2n = []
    pak.n2i = {}
    hashes = []
    music = original_path.stem == 'music_definitions' # WIP: applies to non-music?
    with original_path.open('rb') as f:
        f.seek(0x20)
        unknown_hash_section = f.read(0x10)
    out.seek(align_pak_entry(0x30 + pak.toc_size))
    #paths = {str(p)[:-4].lower(): p for p in fsb_p.glob('**/*.fsb')}
    #for h, p in zip(*sorted(zip((fnv1a(p) for p in paths.keys()), paths.keys())))
    for i, path in enumerate(entries):
        with path.open('rb') as f:
            yield fsb5_parse(f, 0, pak)
            f.seek(0)
            o = out.tell()
            s = out.write(f.read())
        p = str(path)[:-4].lower()
        h = next(e._hash for e in pak.entries if e.path.rsplit('\\', 1)[-1] == path.stem
            ) if music else fnv1a(p) # or crc https://www.askpython.com/python/examples/crc-16-bit-manual-calculation ?
        out.seek(-s % 0x0800, 1)
        hashes.append(h)
        entries[i] = PAK_Entry(p, h, o, s)
    pak.nt_offset = out.tell()
    nt_offset = 4 * new_count
    offsets = []
    pak.entries = []
    with BytesIO() as ntms:
        for h, e in sorted(zip(hashes, entries)):
            pak.entries.append(e)
            out.write(pack(f'<I', nt_offset + ntms.tell()))
            ntms.write(e.path.encode('utf-8'))
            ntms.write(b'\x00')
            offsets.extend([e.offset, e.size, 0xFFFFFFFF])
        pak.nt_size = nt_offset + ntms.tell()
        out.write(ntms.getbuffer())
    out.seek(0)
    out.write(ID_IGA[::-1])
    out.write(pack('>7I', pak.version, pak.toc_size, pak.num_files, pak.alignment, pak.hash_slop, pak.nt_offset, pak.nt_size))
    out.write(unknown_hash_section)
    out.write(pack(f'>{new_count}I', *(e._hash for e in pak.entries)))
    out.write(pack(f'>{new_count * 3}I', *offsets))


# ── IGX ───────────────────────────────────────────────────────────────────

#CAudioArchive        # version 8
#CSoundList           # version 0
#CSound               # version 3
#CSubSoundList        # version 0
#CSubSound            # version 4
#CMusicDefinitionList # version 0
#CMusicDefinition     # version 11
#CTrackInfoList       # version 0
#CTrackInfo           # version 0
#CSoundProperties     # version 7
#CSpeakerVolumes      # version 0
#igObjectList seemingly a bug in daredevil_bank.igx


# ─────────────────────────────────────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────────────────────────────────────

class MUA2GUI(CTk):
    def __init__(self, title: str):
        super().__init__()

        self.title(title)
        #self.geometry('1440x900') # WIP
        #self.configure(fg_color=C_BG)
        #self.minsize(1100, 700) # WIP: Only Actions resizes a lot

        self._pak_path: Path|None = None
        self._igx_path: Path|None = None
        self._pak  : PAK_Header_V4|None = None
        self._igx  : ET.Element|None = None
        self._fsbs : list = []
        self._p_i2n: list = []
        self._p_n2i: list = []
        self._prop_current: str = ''
        self._prop_showing: str = ''
        self._selected_index: int = 0
        self._filter_text = StringVar()
        #self._filter_text.trace_add('write', lambda *_: self._apply_filter())

        AppearanceModeTracker.add(self._set_treeview_theme)
        self.treestyle = Style()
        self.treestyle.theme_use('default')
        self._set_treeview_theme('')
        self._build_layout(title)
        self.log(f'{title} ready.', 'accent')

    # ── Layout ───────────────────────────────────────────────────────────

    def _build_layout(self, title: str):
        # ── Fonts ──
        font_default = CTkFont(FONT, 11)
        font_console = CTkFont(FONT, 10)
        font_title2 = CTkFont(FONT, 13, 'bold')
        btn_cfg = {'font': CTkFont(FONT, 12, 'bold'), 'corner_radius': 6, 'height': 30}

        # ── Top bar ──
        top = CTkFrame(self, corner_radius=0, fg_color='transparent', height=54)
        top.pack(fill='x', side='top')

        CTkLabel(top, text=title,
                     font=CTkFont(FONT, 17, 'bold'),
                     text_color=C_ACCENT).pack(side='left', padx=18, pady=14)


        # WIP: Duplicate buttons
        for label, cmd in (
            ('Load IGX',  self.load_igx),
            ('Load PAK',  self.load_pak),
            #('Extract All', self.extract_all),
            #('Repack',    self.repack),
        ):
            CTkButton(top, text=label, command=cmd, width=110, **btn_cfg).pack(
                side='left', padx=5, pady=12)

        # hash field
        CTkButton(top,
                  text='Hash', command=self._do_hash, width=60, **btn_cfg
                  ).pack(side='right', padx=6, pady=12)
        self._hash = CTkEntry(top,
                              width=220, font=font_default,
                              placeholder_text='FNV-1a hash input…')
        self._hash.pack(side='right', pady=12)
        self._hash.bind('<Return>', lambda e: self._do_hash())
        CTkLabel(top,
                 text='FNV-1a:', font=font_default,
                 text_color=C_DIMTEXT).pack(side='right', padx=(8,4), pady=12)

        # ── Main area ──
        main = CTkFrame(self, fg_color='transparent') #, fg_color=C_BG
        main.pack(fill='both', expand=True)

        # Left pane (tree + search) | widgets had fg_color=C_PANEL
        left = CTkFrame(main, corner_radius=0, fg_color='transparent', width=380)
        left.pack(side='left', fill='y')
        left.pack_propagate(False)

        # search bar
        CTkEntry(left, textvariable=self._filter_text,
                 #placeholder_text='🔍 Search sounds…',
                 font=font_default).pack(fill='x', padx=8, pady=(8,4))

        # tab buttons
        self._tab_var = StringVar(value='fsb')
        #tab_row = CTkFrame(left) #, fg_color=C_PANEL
        #tab_row.pack(fill='x', padx=8, pady=(0,4))
        #for label, val in [('FSB Files', 'fsb'), ('Sounds (IGX)', 'igx')]:
        #    CTkRadioButton(tab_row, text=label, variable=self._tab_var,
        #                       value=val, command=self._apply_filter,
        #                       font=font_default).pack(side='left',padx=6)

        # listbox (with scrollbar)
        lbframe = CTkFrame(left) #, fg_color=C_BG
        lbframe.pack(fill='both', expand=True, padx=8, pady=(0,8))
        '''
        self._lb = Listbox(lbframe,
            bg=C_BG, fg=C_TEXT, selectbackground=C_ACCENT,
            selectforeground=C_BG, activestyle='none',
            font=(FONT, 11), relief='flat', bd=0,
            highlightthickness=0)
        self._lb.configure(yscrollcommand=sb.set)
        self._lb.pack(fill='both', expand=True)
        self._lb.bind('<<ListboxSelect>>', self._on_select)
        self._lb.bind('<Double-Button-1>', lambda e: self._extract_selected())
        '''

        # We could use columns to display additional info
        self.treestyle.configure('Treeview', font=(FONT, 12))
        self.treeview = Treeview(lbframe, height=6, selectmode='browse', show='tree')
        sb = CTkScrollbar(lbframe, command=self.treeview.yview)
        sb.pack(side='right', fill='y')
        self.treeview.configure(yscrollcommand=sb.set)
        self.treeview.pack(fill='both', expand=True, padx=6, pady=6)
        self.bind('<<TreeviewSelect>>', lambda e: self._on_select())

        # Right pane — tabbed detail + log
        right = CTkFrame(main, corner_radius=0, fg_color='transparent')
        right.pack(side='left', fill='both', expand=True)

        # detail area
        self._detail_tabs = CTkTabview(right, command=self._show_data)
        self._detail_tabs._segmented_button.configure(font=font_default)
        self._detail_tabs.pack(fill='both', expand=True, padx=6, pady=(6,3))

        self._detail_tabs.add('Actions')
        inner = CTkScrollableFrame(self._detail_tabs.tab('Actions'))
        inner.pack(fill='both', expand=True)

        CTkLabel(inner, text='Selected FSB',
                     font=font_title2,
                     text_color=C_ACCENT).pack(anchor='w', padx=14, pady=(14,4))

        self._b_efsb = CTkButton(inner, text='⬇  Extract selected FSB',
                  command=self._extract_selected, state='disabled',
                  text_color=C_BG, **btn_cfg
                  )
        self._b_efsb.pack(fill='x', padx=14, pady=4)

        self._b_rfsb = CTkButton(inner, text='🔄  Replace FSB in-place',
                  command=self._replace_selected, state='disabled',
                  text_color=C_BG, **btn_cfg
                  )
        self._b_rfsb.pack(fill='x', padx=14, pady=4)

        self._b_rfsbm = CTkButton(inner, text='🔄  Replace FSB with multi-track',
                  command=self._replace_selected_multi, state='disabled',
                  text_color=C_BG, **btn_cfg
                  )
        self._b_rfsbm.pack(fill='x', padx=14, pady=4)

        CTkLabel(inner, text='Whole PAK',
                 font=font_title2, text_color=C_ACCENT
                ).pack(anchor='w', padx=14, pady=(18,4))

        self._b_ea = CTkButton(inner, text='📦  Extract ALL FSBs',
                  command=self.extract_all, state='disabled',
                  fg_color=C_PURPLE, text_color=C_BG, **btn_cfg
                  )
        self._b_ea.pack(fill='x', padx=14, pady=4)

        self._b_rep = CTkButton(inner, text='🔨  Repack PAK from folder',
                  command=self.repack, state='disabled',
                  fg_color=C_GREEN, text_color=C_BG, **btn_cfg
                  )
        self._b_rep.pack(fill='x', padx=14, pady=4)

        CTkLabel(inner, text='Info',
                 font=font_title2, text_color=C_ACCENT
                ).pack(anchor='w', padx=14, pady=(18,4))

        # WIP: Disable buttons when certain functions are unavailable (_action_info in the original app)

        self._fsb_text = self._build_tab('FSB Properties', COLOR_TAGS_PROPERTY, font_default)
        self._igx_text = self._build_tab('IGX Properties', COLOR_TAGS_PROPERTY, font_default)

        # log
        CTkLabel(right, text='LOG', font=CTkFont(FONT, 10, 'bold'),
                     text_color=C_DIMTEXT).pack(anchor='w', padx=10, pady=(4,0))
        #self._log_box = Text(right, bg=C_BG, fg=C_TEXT,
        #                        font=(FONT, 10), relief='flat',
        #                        state='disabled', wrap='word', bd=0,
        #                        highlightthickness=0)
        self._log_box = CTkTextbox(right,
                                   font=font_console, height=140,
                                   state='disabled', wrap='word')
        self._log_box.pack(anchor='s', fill='x', padx=10, pady=(0,10))

        for tag, col in COLOR_TAGS:
            self._log_box.tag_config(tag, foreground=col)

    def _build_tab(self, name: str, colors: tuple, font: CTkFont) -> CTkTextbox:
        self._detail_tabs.add(name)
        tb = CTkTextbox(self._detail_tabs.tab(name),
                        font=font, wrap='word', state='disabled')
        tb.pack(fill='both', expand=True)
        for tag, col in colors:
            tb.tag_config(tag, foreground=col)
        return tb

    def _configure_buttons(self, state: str):
        self._b_ea.configure(state=state)
        self._b_rep.configure(state=state)

    def _set_treeview_theme(self, theme: str):
        #WIP: does _apply_appearance_mode already get the changed colour?
        bg_color = self._apply_appearance_mode(ThemeManager.theme['CTkFrame']['fg_color'])
        text_color = self._apply_appearance_mode(ThemeManager.theme['CTkLabel']['text_color'])
        selected_color = self._apply_appearance_mode(ThemeManager.theme['CTkButton']['fg_color'])

        self.treestyle.configure('Treeview', background=bg_color, foreground=text_color, fieldbackground=bg_color, borderwidth=0)
        self.treestyle.map('Treeview', background=[('selected', bg_color)], foreground=[('selected', selected_color)])

    # ── Logging ──────────────────────────────────────────────────────────

    def log(self, msg: str, color_level: str = 'accent'):
        self._log_box.configure(state='normal')
        self._log_box.insert('end', f'[{datetime.now().strftime("%H:%M:%S")}] ', 'dim')
        self._log_box.insert('end', f'{msg}\n', color_level)
        self._log_box.configure(state='disabled')
        self._log_box.see('end')

    # ── File loading ─────────────────────────────────────────────────────

    def load_pak(self):
        path = filedialog.askopenfilename(parent=self,
            title='Load PAK file',
            filetypes=(('PAK files', '*.pak *.arc *.bld'), ('All files', '*.*')))
        if not path: return
        p = Path(path)
        self.read_pak(p)
        if self._igx_path and p.stem == self._igx_path.stem: return
        igx = p.parent / '..' / (p.stem + '.igx')
        if not igx.exists(): igx = p.with_suffix('.igx')
        self._igx_path = igx
        self.read_igx(str(igx), igx.name)
        if self._igx: return
        try:
            self.treeview.delete('root')
        except:
            pass
        self.treeview.insert('', '0', 'root', text=p.stem)
        self.treeview.insert('root', '0', 'noinfo', text='FSBs')
        for n in self._pak.i2n:
            self.treeview.insert('noinfo', 'end', n, text=n)

    def load_igx(self):
        path = filedialog.askopenfilename(
            title='Load IGX file',
            filetypes=(('IGX files', '*.igx'), ('All files', '*.*')))
        if not path: return
        p = self._igx_path = Path(path)
        self.read_igx(path, p.name)
        if self._pak_path and p.stem == self._pak_path.stem: return
        pak = p.parent / '..' / (p.stem + '.pak')
        self.read_pak(pak if pak.exists() else p.with_suffix('.pak'))

    def read_pak(self, path: Path):
        try:
            with path.open('rb') as f:
                e = ID_IGA_BYENDIAN[f.read(4)]
                hdr = PAK_Header_V4(*unpack_from(f'{e}7I', f.read(7 * 4)))
                c = hdr.num_files
                f.seek(0x30)
                data = f.read(hdr.toc_size)
                if hdr.nt_offset and c:
                    f.seek(hdr.nt_offset)
                    strings = read_string_table(f.read(hdr.nt_size), c, hdr.nt_size)
                else:
                    strings = ('' for _ in range(c))
                hashes = iter_unpack(f'{e}I', data[:c * 4])
                hdr.entries = [PAK_Entry(next(strings), next(hashes)[0],
                                    *unpack_from(f'{e}3I', data, o))
                    for o in range(c * 4, hdr.toc_size, 12)]
                if c == 1 and hdr.entries[0].path[-4:].lower() == '.igx':
                    igx = hdr.entries[0]
                    f.seek(igx.offset)
                    self._igx = ET.fromstring(f.read(igx.size))
                    self._igx_path = path
                    c = self._populate_treeview(self._igx)
                    self._fsbs = []
                    self._pak = None
                    self._configure_buttons(state='disabled')
                    self.log(f'PAK loaded: {path.name}  (IGX, {c} sounds)', 'green')
                else:
                    # Assume FSB
                    # WIP: Handle None FSBs?
                    self._fsbs = [fsb5_parse(f, e.offset, hdr) for e in hdr.entries]
                    self._pak = hdr
                    self._pak_path = path
                    self._configure_buttons(state='normal')
                    self.log(f'PAK loaded: {path.name}  ({c} FSBs)', 'green')
        except Exception as e:
            self._configure_buttons(state='disabled')
            self.log(f'PAK load error: {e}', 'red')
            messagebox.showerror('Error', str(e))

    def read_igx(self, path: str, name: str):
        try:
            self._igx = ET.parse(path).getroot()
            c = self._populate_treeview(self._igx)
            self.log(f'IGX loaded: {name}  ({c} sounds)', 'green')
        except Exception as e:
            self._igx = None
            self.log(f'IGX load error: {e}', 'red')
            messagebox.showerror('Error', str(e))

    # ── Treeview / filter ────────────────────────────────────────────────────

    def _populate_treeview(self, root: ET.Element) -> int:
        try:
            self.treeview.delete('root')
        except:
            pass
        root_name = root.get('name') # to check external reference (probably none)
        self.treeview.insert('', '0', 'root', text=root_name)

        # All nodes have a 'root' attribute that's always set to 'true', so we skip that
        # All nodes have a 'version' attribute (int), related to type. we should document this to learn
        # Most nodes have a 'comment' attribute (description, creator[dbg_contact_list.ddilallo], creation_time, owner, cloned-from/cloned from[some], original_owner[some]); (). Probably not needed.
        count = 0
        a = root.find('object[@type="CAudioArchive"]')
        if a is None: # checking "if not a:" is deprecated
            for md in get_list_elements(root.find('object[@type="CMusicDefinitionList"]'), root):
                #CMusicDefinition
                name = md.get('refname') #or md.get('buildInfo')[1] or [0] or md.find('var[@name="_name"]').get('value') or original_wav_name
                #original_wav_name = md.find('var[@name="_fileName"]').get('value')
                #bpm = md.find('var[@name="_beatsPerMinute"]').get('value')
                #_ = md.find('var[@name="_duckingGroup"]').get('value')
                self.treeview.insert('root', 'end', f'music::{name}', text=name)
                count += 1
        else:
            #name = a.find('var[@name="_name"]').get('value')
            #other attributes: _protectionName (root_name simplified?), _protectionCategory, _default ('True', common banks)
            file, ref = a.find('var[@name="_soundList"]').get('ref').split('.')
            #assert file == root_name # should always be the case
            for snd in get_list_elements(root.find(f'object[@refname="{ref}"]'), root):
                #assert snd.get('type') == 'CSound'
                #WIP: Possibly add a subsounds count to the text
                parent_id = snd.get('refname')
                self.treeview.insert('root', 'end', parent_id,
                    text=snd.find('var[@name="_name"]').get('value')) # except: name = ref

                # subsounds
                file, ref = snd.find('var[@name="_subSoundList"]').get('ref').split('.')
                #assert file == root_name # should always be the case
                for ss in get_list_elements(root.find(f'object[@refname="{ref}"]'), root):
                    #assert snd.get('type') == 'CSubSound'
                    fsb_name, sound_name = ss.get('buildInfo').split('.')
                    try:
                        self.treeview.insert(parent_id, 'end', ss.get('refname'), text=fsb_name)
                    except:
                        self.treeview.insert(parent_id, 'end', f"{ss.get('refname')}{count}", text=fsb_name)
                    count += 1

        return count

    def _apply_filter(self, *_):
        # WIP
        q   = self._filter_text.get().lower()
        tab = self._tab_var.get()
        self._lb.delete(0,'end')

        self._lb_items = []
        if tab == 'fsb':
            for i, f in enumerate(self._fsbs):
                label = f'{i:4d}  {f.files[0].name}'
                if q and q not in label.lower(): continue
                self._lb.insert('end', label)
                self._lb_items.append(('fsb', i))
        else:
            for i, s in enumerate(self._sounds):
                label = s['name']
                if q and q not in label.lower(): continue
                self._lb.insert('end', label)
                self._lb_items.append(('igx', i))

    def _on_select(self):
        # WIP: Fix colours (working in dark and light)
        self._b_efsb.configure(state='disabled')
        self._b_rfsb.configure(state='disabled')
        self._b_rfsbm.configure(state='disabled')
        sel = self.treeview.selection()
        if not sel: return
        tvi = sel[0]
        parent = self.treeview.parent(tvi)
        if not parent: return
        name = self.treeview.item(tvi)['text']
        music = tvi.split('::', 1)[0] == 'music'
        if parent == 'root' and not music:
            self._prop_current = tvi
            self.log(f'{name}: {len(self.treeview.get_children(tvi))} Subsounds')
        else:
            if music:
                self._igx_text.configure(state='normal')
                self._igx_text.delete('1.0', 'end')
                parent = ''
                e = self._igx.find(f'object[@refname="{name}"]')
                assert e.get('type') == 'CMusicDefinition'
                for v in e.findall('var'):
                    if (n := v.get('name')) != '_trackList':
                        self._igx_text.insert('end', f'{n:>33} ', 'accent')
                        self._igx_text.insert('end', v.get('value'), 'val')
                        self._igx_text.insert('end', '\n')
                self._igx_text.insert('end', '\n')
                file, ref = e.find('var[@name="_trackList"]').get('ref').split('.')
                # Note: all lists should have 16 tracks
                for tr in get_list_elements(self._igx.find(f'object[@refname="{ref}"]'), self._igx):
                    self._igx_text.insert('end', f'{tr.get("refname"):>33} ', 'accent')
                    self._igx_text.insert('end', tr.find('var[@name="_channelType"]').get('value') + '\n', 'val')
                self._igx_text.configure(state='disabled')
            self._b_efsb.configure(state='normal')
            self._b_rfsb.configure(state='normal')
            self._b_rfsbm.configure(state='normal')
            self._prop_current = parent
            idx = self._pak.n2i.get(name.lower())
            if idx is None:
                self.log(f'FSB "{name}" not found in the loaded .pak.', 'red')
            else:
                self._show_fsb(idx)
                self._selected_index = idx
            #if self._igx is None:
            #    pass
            #else:
            #    s = self._igx.find(f'object[@refname="{tvi}"]')
                #original_wav_name = s.find('var[@name="_fileName"]').get('value')
                #original_duration = s.find('var[@name="_length"]').get('value')
                #original_quality  = s.find('var[@name="_quality"]').get('value')

                #_set_action_info
                #self.log(f"IGX Sound: {s['name']}\n"
                #        f"Subsounds: {len(s['subsounds'])}\n"
                #        f'Looping: {looping}\n'
                #        f'Channel: {channel}')
        self._show_data()

    # ── Detail displays ──────────────────────────────────────────────────

    def _show_data(self):
        if self._prop_showing == self._prop_current: return
        if self._igx is None or self._detail_tabs.get() != 'IGX Properties': return
        self._prop_showing = self._prop_current

        p = self._igx.find(f'object[@refname="{self._prop_current}"]')
        file, ref = p.find('var[@name="_data"]').get('ref').split('.')
        #assert file == root_name
        data = self._igx.find(f'object[@refname="{ref}"]')
        #loop = False if (l := data.find('var[@name="_looping"]')) is None else l.get('value') in ('true', 'True')
        #_channelGroupName
        #_delay
        #_duckingAmount
        #_duckingGroup
        #_fadeIn
        #_fadeOut
        #_looping
        #_max3d
        #_maxPlaybacks
        #_min3d
        #_pitch
        #_pitchRandomnessRange
        #_playBehavior
        #_playFeature
        #_priority
        #_soundGroupName
        #_streaming
        #_volume
        #_volumeRandomnessRange
        #_speakerVolumes
        #_threeDBehavior
        #_numSubSoundsToLoad
        #_beatsPerMinute
        #_beatIncrement
        #_nextSound
        #_pauseType
        #_soundToSyncWith
        #_aiControlledHeroDuckingFactorStorage (rare)
        #_aiControlledHeroDuckingFactor
        #_playPercentage
        #_duckingInverted
        #_useDuckingGainDirectly
        #_stopMasterSound

        #_centerVolume
        #_leftBackVolume
        #_leftFrontVolume
        #_lowFrequencyVolume
        #_rightBackVolume
        #_rightFrontVolume

        #stream_tag = 'green' if streaming == 'true' else 'dim'
        # WIP: Allow config to change alignment of properties
        self._igx_text.configure(state='normal')
        self._igx_text.delete('1.0', 'end')
        for v in data.findall('var'):
            name = v.get('name')
            self._igx_text.insert('end', f'{name:>38} ', 'accent')
            if name == '_speakerVolumes' and (ref := v.get('ref')):
                file, ref = ref.split('.')
                sv = self._igx.find(f'object[@refname="{ref}"]') #CSpeakerVolumes
                for v in sv.findall('var'):
                    self._igx_text.insert('end', '\n')
                    self._igx_text.insert('end', f'{v.get("name"):>38} ', 'accent2')
                    self._igx_text.insert('end', v.get('value'), 'val')
            else:
                self._igx_text.insert('end', v.get('value'), 'val')
            self._igx_text.insert('end', '\n')
        self._igx_text.configure(state='disabled')

    def _fsb_sound_to_print(self, sound: FSB_Sound_Header) -> list[tuple[str]]:
        samples = sound.samples
        freq = sound.frequency
        dur  = (samples / freq) if freq else 0
        texts = [
            ('── AUDIO\n', 'accent2'),
            ('  Name         ', 'accent'), (f'{sound.name}\n', 'val'),
            ('  Channels     ', 'accent'), (f'{sound.channels}\n', 'val'),
            ('  Sample rate  ', 'accent'), (f'{freq} Hz\n', 'val'),
            ('  Duration     ', 'accent'), (f'{dur:.3f} s\n', 'val'), # or 2f?
            ('  Samples      ', 'accent'), (f'{samples:,}\n', 'val')
            ]
        for t, v in sound.other_info.items():
            texts += [
              ('  UA2 loop inf ', 'accent'), (', '.join(f'{n:,}' for n in unpack_from(f'<{len(v) // 4}I', v)), 'val'), (' (samples)\n', 'val')
            ] if t == 5 else [
              (f'  info{t}        ', 'accent'), (v.hex('-', -4), 'val'), ('\n', 'val')
            ]
        if sound.loop_start is None:
            texts.append(('  No loop points\n', 'dim'))
        else:
            texts += [
            ('\n', 'green'),
            ('── LOOP\n', 'green'),
            ('  Loop points  ', 'accent'), (f'{sound.loop_start:,} → {sound.loop_end:,} (samples)\n', 'green'),
            ('  Loop duration', 'accent'), (f'{(sound.loop_end - sound.loop_start) / freq * 1000:.1f} ms\n', 'green'),
            ]
        return texts

    def _show_fsb(self, index: int):
        fsb = self._fsbs[index]
        texts = [
            ('── FSB5 FILE\n', 'accent2'),
            #('  Name         ', 'accent'), (f'{sound.name}\n', 'val'),
            ('  Format       ', 'accent'), (f'{fsb.fmt.name} v{fsb.fmt_version >> 16}\n', 'val'),
            ('  Index        ', 'accent'), (f'{index}\n', 'val'),
            ('  Offset       ', 'accent'), (f'0x{self._pak.entries[index].offset:08X}\n', 'val'),
            ('  Total size   ', 'accent'), (f'{fsb.total_size:,} bytes\n', 'val'),
            ('  Audio data   ', 'accent'), (f'{fsb.audio_size:,} bytes\n\n', 'val'),
            #('  Version      ', 'accent'), (f'{fsb.version}\n', 'val'),
            #('  File Count   ', 'accent'), (f'{fsb.file_count}\n', 'val'),
            #('  samplehdr_size  ', 'accent'), (f'{fsb.samplehdr_size:,} bytes\n', 'val'),
            #('  name_size    ', 'accent'), (f'{fsb.name_size:,} bytes\n', 'val'),
        ] + self._fsb_sound_to_print(fsb.files[0])
        #or:
        #for ss in fsb.files:
        #    self._fsb_sound_to_print(ss)

        self._fsb_text.configure(state='normal')
        self._fsb_text.delete('1.0', 'end')
        for text, tag in texts:
            self._fsb_text.insert('end', text, tag)
        self._fsb_text.configure(state='disabled')

        # Action info
        #_set_action_info
        #self.log(
        #    f'Selected FSB #{index}: {{sound.name}}\n'
        #    f"Size: {fsb['total_size']:,} bytes\n"
        #    f"Slot (aligned): {align_pak_entry(fsb['total_size']):,} bytes\n\n"
        #    f"Replacement FSB must be ≤ {align_pak_entry(fsb['total_size']):,} bytes\n"
        #    f'for in-place replace. Otherwise use Repack.'
        #)

        #_set_action_info

    # ── Actions ──────────────────────────────────────────────────────────

    def _extract_selected(self):
        if self._pak is None:
            messagebox.showinfo('Info', 'Load a PAK first.')
            return
        idx = self._selected_index
        f = self._fsbs[idx]
        dest = filedialog.asksaveasfilename(
            title='Save FSB', defaultextension='.fsb',
            initialfile=f'{f.files[0].name}.fsb' if f.files else f'{idx:04d}.fsb',
            filetypes=[('FSB files', '*.fsb'), ('All', '*.*')])
        if not dest: return
        try:
            e = self._pak.entries[idx]
            with self._pak_path.open('rb') as f:
                f.seek(e.offset)
                Path(dest).write_bytes(f.read(e.size))
            self.log(f'Extracted PAK[{idx}] → {dest}', 'green')
        except Exception as e:
            self.log(f'Extract error: {e}', 'red')

    def extract_all(self):
        #if self._pak is None:
        #    messagebox.showinfo('Info', 'Load a PAK first.')
        #    return
        out_dir = filedialog.askdirectory(title='Output directory for FSBs', initialdir=self._pak_path.parent)
        if not out_dir: return
        def _run():
            try:
                out = Path(out_dir) / self._pak_path.stem
                with self._pak_path.open('rb') as f:
                    for e in self._pak.entries:
                        p = Path(e.path if e.path else hex(e.offset))
                        fpath = out / p.relative_to(p.anchor).with_suffix('.fsb')
                        #if p.is_absolute() else p)
                        fpath.parent.mkdir(parents=True, exist_ok=True)
                        f.seek(e.offset)
                        fpath.write_bytes(f.read(e.size))
                self.log(f'Extracted {self._pak.num_files} FSBs → {out_dir}', 'green')
            except Exception as e:
                self.log(f'Extract all error: {e}', 'red')
        Thread(target=_run, daemon=True).start()

    def _replace_selected_multi(self):
        in_dir = filedialog.askdirectory(title='Directory with individual channel files')
        if not in_dir: return
        self._replace_index(self._selected_index, Path(in_dir))

    def _replace_selected(self):
        if self._pak is None:
            messagebox.showinfo('Info', 'Load a PAK first.')
            return
        new_fsb = filedialog.askopenfilename(
            title='Select replacement FSB',
            filetypes=[('FSB files', '*.fsb'), ('All', '*.*')])
        if not new_fsb: return
        idx = self._selected_index
        new_fsb = Path(new_fsb)
        #out = filedialog.asksaveasfilename(
        #    title='Save new PAK', defaultextension='.pak',
        #    initialfile=self._pak_path.name,
        #    filetypes=[('PAK files', '*.pak *.arc *.bld'), ('All', '*.*')])
        self._replace_index(idx, new_fsb, new_fsb.stat().st_size > align_pak_entry(self._pak.entries[idx].size))

    def _replace_index(self, index: int, new_fsb: Path, bigger: bool = True):
        try:
            entry = self._pak.entries[index]
            with self._pak_path.open('rb+') as f:
                e = ID_IGA_BYENDIAN[f.read(4)]
                if bigger:
                    later_data_offset = min(en.offset for en in self._pak.entries if en.offset > entry.offset)
                    f.seek(later_data_offset)
                    later_data = f.read()
                f.seek(entry.offset)
                new_fsb = self._read_fsb(new_fsb, index)
                sz = f.write(new_fsb.read_bytes())
                ons_offset = 0x30 + self._pak.num_files * 4
                if bigger:
                    f.seek(-sz % 0x0800, 1)
                    offset_shift = f.tell() - later_data_offset
                    f.write(later_data)
                    for i, en in enumerate(self._pak.entries):
                        if en.offset > entry.offset:
                            en.offset += offset_shift
                            f.seek(ons_offset + i * 12)
                            _ = f.write(pack(f'{e}I', en.offset))
                f.seek(ons_offset + index * 12 + 4)
                _ = f.write(pack(f'{e}I', sz))
                entry.size = sz
            self.log(f'Replaced {self._pak_path.name}[{index}] → {new_fsb.name}', 'green')
        except Exception as e:
            self.log(f'Replace error: {e}', 'red')
            messagebox.showerror('Error', str(e))
            # WIP: add traceback.format_exc()

    def repack(self):
        if not self._pak:
            messagebox.showinfo('Info', 'Load a PAK first.')
            return
        fsb_dir = filedialog.askdirectory(
            title='Select folder with FSBs to rebuild')
        if not fsb_dir: return
        fp = Path(fsb_dir)
        out = filedialog.asksaveasfile(mode='wb',
            title='Save repacked PAK', defaultextension='.pak',
            initialdir=fp.parent, initialfile=f'{fp.stem}.pak',
            filetypes=[('PAK files', '*.pak *.arc *.bld'), ('All', '*.*')])
        if not out: return
        def _run():
            try:
                self._fsbs = list(pak_repack(self._pak_path, out, fp, self._pak))
                self.log(f'Repacked {self._pak.num_files} FSBs → {out.name}', 'green')
            except Exception as e:
                self.log(f'Repack error: {e}', 'red')
                messagebox.showerror('Error', str(e))
            out.close()
        Thread(target=_run, daemon=True).start()

    def _read_fsb(self, path: Path, index: int) -> Path:
        if path.suffix.lower() != '.fsb':
            #'fsbankexcl' instead of FSBANKEXCL
            run([FSBANKEXCL, '-o', path.with_suffix('.fsb'), path, '-format', 'MP2', '-quality', '70', '-build_mode', 'i', '-cache_dir', 'cache/'], check=True)
            path = path.with_suffix('.fsb')
        with path.open('rb') as fsb:
            self._fsbs[index] = fsb5_parse(fsb, 0, self._pak)
        return path

    def _do_hash(self):
        text = self._hash.get().strip()
        if not text: return
        h = fnv1a(text)
        self.log(f'FNV-1a  {text!r}  →  0x{h:08X}  ({h})', 'accent')


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app = MUA2GUI('MUA2 Sound Bank Editor')
    app.mainloop()
