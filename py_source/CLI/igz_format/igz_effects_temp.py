"""
MUA2 IGZ Effect Tool  —  Unpack / Info / Repack
=================================================
Reverse-engineered from MUA2 RE Steam (WIN64, IGZ v6) PDB symbols + binary analysis.

CONFIRMED LAYOUTS
-----------------
CFxTemplate  (effect container):
  +0x000  __type_idx   u64    metatype index (structural)
  +0x008  firstTemplate u32   ptr to primitive list (structural)
  +0x020  loopTime     f32    effect loop duration in seconds
  +0x02C  poolID       u32    render pool/priority (default 54)
  +0x030  loopCount    u32    loop count (default 2)
  +0x040  persistLoop  u32    persist loop flag
  +0x044  randLoopTime u32    random loop time flag
  +0x048  __handlePtr  u32    NULL ptr (structural)
  +0x050  __strRefOff  u32    string ref offset (structural)
  +0x058  __uid_lo     u32    unique ID low  — DO NOT EDIT
  +0x05C  __uid_hi     u32    unique ID high — DO NOT EDIT
  +0x060  __flag_c     u32    internal flag
  +0x070  __flag_d     u32    internal flag
  +0x074  __flag_e     u32    internal flag
  +0x078  __handlePtr2 u32    NULL ptr (structural)
  +0x080  __strRefOff2 u32    string ref 2 offset (structural)

CFxPrimitiveTemplate  (actual particle effect):
  +0x000  __type_idx   u64    metatype index (structural)
  +0x008  type         u32    primitive type enum (2=Trail, 3=Sprite, etc.)
  +0x010  __namePtr    u64    name string ptr (structural)
  
  --- CRangedFloat fields (each 32 bytes: value f32 | min f32 | max f32 | pad 20b) ---
  +0x018  rqSize       CRF    particle size/width
  +0x038  rqAlpha      CRF    opacity
  +0x058  rqLength     CRF    trail length
  +0x078  rqOffset     CRF    position offset
  +0x098  rqRotation   CRF    rotation angle
  +0x0B8  rqRotationRadius  CRF    rotation radius
  +0x0D8  rqChaos      CRF    chaos/noise amount
  +0x0F8  rqAttenuation CRF   attenuation
  +0x118  rqStartArc   CRF    arc start angle
  +0x138  rqEndArc     CRF    arc end angle
  +0x158  rqSize2      CRF    secondary size
  +0x178  rqUVScroll   CRF    UV scroll speed
  +0x198  rqUVScale    CRF    UV scale
  
  --- CRangedVector fields (each 3 × CRF for x, y, z = 96 bytes) ---
  +0x1B8  rvOrigin     CRV    emission origin offset
  +0x218  rvVelocity   CRV    initial velocity
  +0x278  rvAcceleration CRV  acceleration vector
  +0x2D8  rvRotationAxis CRV  rotation axis
  +0x338  rvOrientAxis CRV    orientation axis
  +0x398  rvOrigin2    CRV    secondary emission origin (partial: x,y only in small files)
  
  --- Packed color fields (each u32 = 0xRRGGBBAA) ---
  +0x3D8  startColor1  u32    start colour 1 (RGBA packed)
  +0x3DC  startColor2  u32    start colour 2 (RGBA packed)
  +0x3E0  midColor1    u32    mid colour 1 (RGBA packed)
  +0x3E4  midColor2    u32    mid colour 2 (RGBA packed)
  +0x3E8  endColor1    u32    end colour 1 (RGBA packed)
  +0x3EC  endColor2    u32    end colour 2 (RGBA packed)

Usage:
  python mua2_igz_tool.py info   effect.igz
  python mua2_igz_tool.py unpack effect.igz  [-o effect.xml]
  python mua2_igz_tool.py repack effect.igz effect_edited.xml  -o effect_mod.igz
"""

import argparse, xml.etree.ElementTree as ET
from enum import auto, Enum
from glob import glob
from pathlib import Path

from igz_reader import IgzReader


class CFxType(Enum):
    Unknown0 = 0
    Unknown1 = auto()
    Trail = auto()
    Sprite = auto()
    Bolt = auto()
    Unknown5 = auto()
    Unknown6 = auto()
    Unknown7 = auto()
    Unknown8 = auto()
    Unknown9 = auto()
    Unknown10 = auto()
    Unknown11 = auto()
    Unknown12 = auto()
    Unknown13 = auto()
    Unknown14 = auto()
    Unknown15 = auto()
    Unknown16 = auto()
    Unknown17 = auto()
    Unknown18 = auto()
    Unknown19 = auto()


# ─── IGZ v6 core ───────────────────────────────────────────────────────────────
'''
class IGZv6:
    MAGIC = 0x49475A01

    def __init__(self):
        self.data      : bytes = b''
        self.pointers  : list  = []
        self.metatypes : list  = []
        self.strings   : list  = []
        self.root_raws : list  = []

    def _u32(self, o): return struct.unpack_from('<I', self.data, o)[0]
    def _u64(self, o): return struct.unpack_from('<Q', self.data, o)[0]
    def _f32(self, o): return struct.unpack_from('<f', self.data, o)[0]

    def fix_ptr(self, r):
        if r & 0x80000000: return -1
        idx = (r >> 0x18) + 1
        return self.pointers[idx] + (r & 0xFFFFFF) if idx < len(self.pointers) else -1

    def metatype_at(self, phys):
        if phys < 0 or phys + 8 > len(self.data): return None
        t = self._u64(phys)
        return self.metatypes[t] if t < len(self.metatypes) else None

    def load(self, path):
        self.data = Path(path).read_bytes()

        if self._u32(0) != self.MAGIC:
            raise ValueError("Not an IGZ file")
        if self._u32(4) != 6:
            raise ValueError(f"Only IGZ v6 supported (got v{self._u32(4)})")

        off = 0x10
        while True:
            ptr = self._u32(off)
            if ptr == 0: break
            self.pointers.append(ptr)
            off += 16

        inner     = self.pointers[0]
        numfixups = self._u32(inner + 0x10)
        pos       = inner + 0x1C

        for _ in range(numfixups):
            if pos + 24 > len(self.data): break
            fid    = self._u32(pos)
            count  = self._u32(pos + 12)
            length = self._u32(pos + 16)
            cabs   = pos + self._u32(pos + 20)

            if fid == 0:
                p = cabs
                for _ in range(count):
                    e = self.data.find(b'\x00', p)
                    self.metatypes.append(self.data[p:e].decode('utf-8','replace') if e!=-1 else '')
                    p = e+1 if e!=-1 else p+1
            elif fid == 1:
                p = cabs
                for _ in range(count):
                    e = self.data.find(b'\x00', p)
                    self.strings.append(self.data[p:e].decode('utf-8','replace') if e!=-1 else '')
                    p = e+1 if e!=-1 else p+1
            elif fid == 8:
                for j in range(count):
                    self.root_raws.append(self._u32(cabs + j*4))

            pos += length

    def iter_list(self, phys):
        count  = self._u32(phys + 0x10)
        mr_ptr = self._u32(phys + 0x20)
        arr    = self.fix_ptr(mr_ptr)
        if arr < 0 or count <= 0 or count > 1000: return
        for i in range(count):
            cr = self._u32(arr + i*4)
            cp = self.fix_ptr(cr)
            mt = self.metatype_at(cp)
            if mt: yield cp, mt

    # ── RGBA helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def rgba_to_str(v):
        r = (v >> 24) & 0xFF
        g = (v >> 16) & 0xFF
        b = (v >>  8) & 0xFF
        a = (v >>  0) & 0xFF
        return f'#{r:02X}{g:02X}{b:02X}{a:02X}'

    @staticmethod
    def str_to_rgba(s):
        s = s.strip().lstrip('#')
        if len(s) == 8:
            r,g,b,a = int(s[0:2],16),int(s[2:4],16),int(s[4:6],16),int(s[6:8],16)
        elif len(s) == 6:
            r,g,b,a = int(s[0:2],16),int(s[2:4],16),int(s[4:6],16),255
        else:
            raise ValueError(f"Cannot parse colour: {s!r}")
        return (r<<24)|(g<<16)|(b<<8)|a

    # ── Read one field value ──────────────────────────────────────────────────
    def read_field(self, phys, off, ftype):
        a = phys + off
        if a + 4 > len(self.data): return None

        if ftype == 'f32':  return self._f32(a)
        if ftype == 'u32':  return self._u32(a)
        if ftype == 'rgba': return self.rgba_to_str(self._u32(a))
        return None

    # ── XML export ────────────────────────────────────────────────────────────
    def _emit(self, parent, phys, mtype, depth=0):
        if depth > 8: return
        el = ET.SubElement(parent, 'object')
        el.set('type', mtype)
        el.set('phys', f'0x{phys:X}')

        if mtype == 'igObjectList':
            for cp, cm in self.iter_list(phys):
                self._emit(el, cp, cm, depth+1)
        elif mtype == 'CFxTemplate':
            self._emit_schema(el, phys, CFX_TEMPLATE_FIELDS)
        elif mtype == 'CFxPrimitiveTemplate':
            self._emit_schema(el, phys, CFX_PRIM_FIELDS)

    def _emit_schema(self, parent, phys, schema):
        for off in sorted(schema):
            name, ftype, editable, desc = schema[off]
            val = self.read_field(phys, off, ftype)
            if val is None: continue

            prop = ET.SubElement(parent, 'property')
            prop.set('name',        name)
            prop.set('type',        ftype)
            prop.set('editable',    'true' if editable else 'false')
            prop.set('value',       f'{val:.8g}' if ftype == 'f32' else str(val))
            prop.set('file_offset', f'0x{phys+off:X}')
            prop.set('desc',        desc)

    # ── Repack ────────────────────────────────────────────────────────────────
    @staticmethod
    def patch_from_xml(original_path, xml_path, output_path):
        igz = IGZv6()
        igz.load(original_path)

        tree   = ET.parse(xml_path)
        buf    = bytearray(igz.data)
        count  = 0
        warns  = []

        for prop in tree.getroot().iter('property'):
            if prop.get('editable', 'true').lower() == 'false':
                continue
            name     = prop.get('name', '')
            if name.startswith('__'):
                continue
            ftype    = prop.get('type', '')
            value    = prop.get('value', '')
            file_off = prop.get('file_offset', '')

            if not file_off or not value: continue
            try: abs_off = int(file_off, 16)
            except ValueError: continue

            if abs_off <= 0 or abs_off + 4 > len(buf):
                warns.append(f"  SKIP {name}: offset 0x{abs_off:X} out of range")
                continue

            # safety: never overwrite null-encoded ptr fields
            cur = struct.unpack_from('<I', buf, abs_off)[0]
            if cur & 0x80000000:
                warns.append(f"  SKIP {name} @ 0x{abs_off:X}: null-ptr field")
                continue

            try:
                if ftype == 'f32':
                    struct.pack_into('<f', buf, abs_off, float(value))
                elif ftype == 'u32':
                    v = int(value, 0) if str(value).startswith('0x') else int(value)
                    struct.pack_into('<I', buf, abs_off, v)
                elif ftype == 'rgba':
                    struct.pack_into('<I', buf, abs_off, IGZv6.str_to_rgba(value))
                else:
                    continue
                count += 1
            except (ValueError, struct.error) as e:
                warns.append(f"  WARN {name} @ 0x{abs_off:X}: {e}")

        Path(output_path).write_bytes(buf)
        if warns:
            print("Warnings:")
            for w in warns: print(w)
        return count
'''

# ─── Commands ──────────────────────────────────────────────────────────────────

#def cmd_info(args):
#    igz = IGZv6(); igz.load(args.igz)
#    print(f"\n{'─'*64}")
#    print(f"  {Path(args.igz).name}")
#    print(f"{'─'*64}")
#    print(f"  IGZ v6  WIN64  {len(igz.data):,} bytes")
#    print(f"  Sections: {[hex(p) for p in igz.pointers]}")
#    print(f"  Metatypes: {igz.metatypes}")
#    if igz.strings: print(f"  Textures:  {igz.strings}")
#
#    print(f"\n  Object tree:")
#    def show(phys, mtype, depth=0):
#        indent = '  ' * (depth+2)
#        print(f"{indent}[{mtype}] @ 0x{phys:X}")
#        if mtype == 'igObjectList':
#            for cp, cm in igz.iter_list(phys):
#                show(cp, cm, depth+1)
#
#    for raw in igz.root_raws:
#        rp = igz.fix_ptr(raw); mt = igz.metatype_at(rp)
#        if mt: show(rp, mt)

def cmd_unpack(input_file: str):
    r = IgzReader(Path(input_file))
    #out = Path(args.output) if args.output else Path(args.igz).with_suffix('.xml')
    #
    #root = ET.Element('igz_effect')
    #root.set('note',
    #    'Edit "value" attributes freely. '
    #    'Fields starting with __ are structural and will NOT be repacked.')
    #he = ET.SubElement(root, 'header')
    #for a, v in r.header.__dict__.values():
    #    he.set(a, v)
    #print(r.TSTR)
    names = r.NAMV6[0]
    for n in r.parseHierarchy():
        # n is igObjectList
        for i, sn in enumerate(n.List):
            print(names[i])
            print(sn)
            print('\n')
    #meta = ET.SubElement(root, 'metadata')
    #ET.SubElement(meta, 'metatypes').text = ', '.join(self.metatypes)
    #if self.strings:
    #    ET.SubElement(meta, 'textures').text = ', '.join(self.strings)
    #
    #objects_el = ET.SubElement(root, 'objects')
    #for raw in self.root_raws:
    #    rp = self.fix_ptr(raw)
    #    mt = self.metatype_at(rp)
    #    if not mt: continue
    #    self._emit(objects_el, rp, mt)
    #
    #ET.indent(root, ' ' * 4)

    #ET.ElementTree(root).write(out, encoding='utf-8')
    #n = sum(1 for _ in root.iter('property'))
    #print(f"Unpacked:  {args.igz}")
    #print(f"       ->  {out}  ({n} properties)")
    #print(f"Metatypes: {igz.metatypes}")
    #if igz.strings: print(f"Textures:  {igz.strings}")

#def cmd_repack(args):
    #n = IGZv6.patch_from_xml(args.igz, args.xml, args.output)
    #orig = Path(args.igz).read_bytes()
    #new  = Path(args.output).read_bytes()
    #diffs = sum(1 for a,b in zip(orig, new) if a!=b)
    #print(f"Original: {args.igz}")
    #print(f"XML:      {args.xml}")
    #print(f"Output:   {args.output}")
    #print(f"Patched:  {n} properties  ({diffs} bytes changed)")

def main():
    p = argparse.ArgumentParser(
        prog='mua2_igz_effects',
        description='MUA2 IGZ Effect Tool — unpack / info / repack',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)

    p.add_argument('input', help='input file (supports glob)')
    #sub = p.add_subparsers(dest='cmd', required=True)

    #i = sub.add_parser('info',   help='Show IGZ structure and object tree')
    #i.add_argument('igz')

    #u = sub.add_parser('unpack', help='Unpack IGZ to editable XML with named fields')
    #u.add_argument('igz')
    #u.add_argument('-o','--output', help='Output XML path (default: <name>.xml)')

    #r = sub.add_parser('repack', help='Patch edited XML values back into IGZ')
    #r.add_argument('igz',  help='Original IGZ (binary base — unchanged except patched fields)')
    #r.add_argument('xml',  help='Edited XML from unpack')
    #r.add_argument('-o','--output', required=True, help='Output IGZ path')

    args = p.parse_args()
    #{'info': cmd_info, 'unpack': cmd_unpack, 'repack': cmd_repack}[args.cmd](args)
    input_files = glob(args.input.replace('[', '[[]'), recursive=True)

    if not input_files:
        raise ValueError('No files found')
    for input_file in input_files:
        #input_file = Path(input_file)
        #if input_file.suffix.casefold() == '.igz':
        cmd_unpack(input_file)
        #else: # assume .xml to combine

if __name__ == '__main__':
    main()