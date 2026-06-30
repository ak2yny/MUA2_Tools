'''IGZ geometry extraction - extracts vertex/index data and walks scene graph.

Produces ParsedGeometry instances compatible with the existing mesh_builder.

Raw vertex/index data is stored sequentially in a pure data section (no objects)
of the IGZ file, ordered by VB/IB block index (field +0x28). Data starts at
section_offset + chunk_alignment (typically +0x10). Blocks are mostly tightly
packed but have small variable-length alignment gaps (0-30 bytes) between them.
A scan-based approach probes forward to locate each block's exact start.

Vertex element layout:
    igigVertexElementMetaField (12 bytes):
        +0: _type (u8)
        +1: _stream (u8)
        +2: _mapToElement (u8)
        +3: _count (u8)
        +4: _usage (u8) - 0=POSITION, 1=NORMAL, 2=TANGENT, 3=BINORMAL,
                          4=COLOR, 5=TEXCOORD, 6=BLENDWEIGHT, 8=BLENDINDICES
        +5: _usageIndex (u8)
        +6: _packDataOffset (u8)
        +7: _packTypeAndFracHint (u8)
        +8: _offset (u16) - byte offset within vertex stride
        +10: _freq (u16)

v6 object field offsets:
    igGeometryAttr (72B):  +0x18=VB ref, +0x20=IB ref
    igVertexBuffer (64B):  +0x10=vertexCount, +0x30=format ref, +0x38=packData
    igVertexFormat (120B): +0x10=vertexSize, +0x18=elementsMemRef, +0x20=elementsDataPtr
    igIndexBuffer  (72B):  +0x10=indexCount, +0x30=primType
'''

from dataclasses import dataclass, field, InitVar
from enum import auto, Enum
import struct
import math


# --- PS3 Enums ---

class PS3Format(Enum):
    Short_Normalized = auto()
    Float_Single     = auto()
    Float_Half       = auto()
    UByte_Normalized = auto()
    Short            = auto()
    _bitwise_stuff   = auto()
    UByte            = auto()
    Fixed            = auto() # FIXED_POINT
    Unit_Vector      = auto()

class PS3VertexUsage(Enum):
    UNKNOWN  = 0
    POSITION = auto()
    NORMAL   = auto()
    TANGENT  = auto()
    BINORMAL = auto()
    UV0      = auto()
    UV1      = auto()
    UV2      = auto()
    UV3      = auto()
    COLOR    = auto()

class EdgeGeomSkin(Enum):
    NONE = 0
    NO_SCALING = auto()
    UNIFORM_SCALING = auto()
    NON_UNIFORM_SCALING = auto()
    SINGLE_BONE_NO_SCALING = auto()
    SINGLE_BONE_UNIFORM_SCALING = auto()
    SINGLE_BONE_NON_UNIFORM_SCALING = auto()


# --- PS3 Geometry classes ---

@dataclass(slots=True)
class EdgeGeomSpuConfigInfo:
    FlagsAndUniformTableCount: int
    CommandBufferHoleSize: int
    InputVertexFormatId: int
    SecondaryInputVertexFormatId: int
    OutputVertexFormatId: int
    VertexDeltaFormatId: int
    IndicesFlavorAndSkinningFlavor: int
    SkinningMatrixFormat: int
    NumVertices: int
    NumIndices: int
    IndicesOffset: int
    # Not part of this struct, but had no where better to put it:
    SkinMatrixOffset0: int
    SkinMatrixOffset1: int
    SkinMatrixSize0: int
    SkinMatrixSize1: int

@dataclass(slots=True)
class PS3MeshObject:
    VertexCount: int
    vertexBuffers: list
    vertexStrides: list
    igVertexElements: list
    IndexCount: int
    IndexBuffer: bytes
    BoneMapIndex: int
    spuConfigInfo: EdgeGeomSpuConfigInfo
    def getBufferForAttribute(self, attributeId: PS3VertexUsage):
        # WIP: Improve with Numpy
        if attributeId == PS3VertexUsage.POSITION and self.igVertexElements[0].Count == 0:
            return EdgeGeometryAttributeBlock().unpack(self.vertexBuffers[0], self.VertexCount, 12)
        for i in range(3): # WIP: clarify buffers count (why 3)
            for elem in self.igVertexElements[i].Elements:
                if elem.edgeAttributeId == attributeId:
                    return elem.unpack(self.vertexBuffers[i], self.vertexCount, self.vertexStrides[i])
        return None
    def getWeightBuffers(self):
         # WIP: See Noesis plugin, but probably not necessary with Numpy array.
         pass

class EdgeGeometryVertexDescriptor:
    def __init__(self, data: bytes):
        self.Count = len(data) and data[0]
        self.VertexStride = len(data) and data[1]
        self.Elements = [EdgeGeometryAttributeBlock(data[i:i + 8])
            for i in range(8, (self.Count + 1) * 8, 8)]

@dataclass
class EdgeGeometryAttributeBlock:
    Offset: int = 0
    Format: PS3Format|int = 2
    ComponentCount: int = 3
    EdgeAttributeId: PS3VertexUsage|int = 1
    Size: int = 0
    VertexProgramSlotIndex: int = 0
    FixedBlockOffset: int = 0
    Padding: int = 0
    def __post_init__(self):
        self.EdgeAttributeId = PS3VertexUsage(self.EdgeAttributeId)
        self.Format = PS3Format(self.Format)
    def unpack(self, vertexBuffer: bytes, vertexCount: int, stride: int):
        # WIP: Needs efficient array method (maybe with Numpy)
        if self.EdgeAttributeId == PS3VertexUsage.POSITION and self.ComponentCount == 4:
            pass
            #return repack_SHORT4Scale4(vertexBuffer, vertexCount * stride, stride)
        return b''.join(self.unpackVertex(vertexBuffer[i:i + stride])
            for i in range(0, vertexCount * stride, stride))
    def unpackVertex(self, data):
        #pack('>f', val)
        if self.Format == PS3Format.Short_Normalized:
            val = unpack_from('>h', data, self.Offset + 2 * i)[0] / 0x7FFF
        elif self.Format == PS3Format.Float_Single:
            val = data # WIP
        elif self.Format == PS3Format.Float_Half:
            val = unpack_from('>e', data, self.Offset + 2 * i)[0]
        elif self.Format == PS3Format.UByte_Normalized:
            val = data[self.Offset + 1 * i] / 0x7F
        elif self.Format == PS3Format.Short:
            val = unpack_from('>h', data, self.Offset + 2 * i)[0]
        elif self.Format == PS3Format._bitwise_stuff:
            raw, = unpack_from('>I', data, self.Offset + 4 * i)
            val = ((raw & 0x000007FF) >> 0) / 0x7FF, ((raw & 0x003FF800) >> 11) / 0x7FF, ((raw & 0xFFC00000) >> 22) / 0x3FF
        elif self.Format == PS3Format.UByte:
            val = data[offset]
        else:
            print('unimplemented format type:', self.Format)
            return None
        return b''.join(unpackFunction(data, self.Offset + 2 * i)
            if i < self.ComponentCount else bytes(4) # 0.0
            if i < 4 else b'\x3F\x80\x00\x00' # 1.0
            for i in range(4))


# --- Enums ---

# Sentinel type value for element list terminator
ELEMENT_TERMINATOR_TYPE = 44  # 0x2C

class IgzPrimitive(Enum): # IG_GFX_DRAW
    POINTS = 0
    LINES = auto()      # likely wrong: found quad-decomposed triangle-list pattern in all MUA2 maps [a,b,c,c,d,a,...] (UNKNOWN IF last-gen or next-gen) # noesis.RPGEO_TRIANGLE
    LINE_STRIP = auto() # noesis.RPGEO_TRIANGLE (worked for MUA2 skins)
    TRIANGLES = auto() # noesis.RPGEO_TRIANGLE # unconfirmed (triangle strip?)
    TRIANGLE_STRIP = auto() # Special Alchemy section checkers
    TRIANGLE_FAN = auto()
    QUADS = auto()
    # WIP: Find Blender equivalent
    # MUA2 PC: value 1 = IG_GFX_DRAW_TRIANGLE_LIST (all 45,759 IBs across 89 maps)

class VertexUsage(Enum):
    POSITION = 0
    NORMAL = auto()
    TANGENT = auto()
    BINORMAL = auto()
    COLOR = auto()
    TEXCOORD = auto()
    BLENDWEIGHT = auto()
    UNUSED_0 = auto()
    BLENDINDICES = auto()
    FOGCOORD = auto()
    PSIZE = auto()

class VertexBufferType(Enum): # designed for v9
    FLOAT1 =             0x00, 1, 'f', 4, 0, 1
    FLOAT2 =             0x01, 2, 'f', 4, 0, 1
    FLOAT3 =             0x02, 3, 'f', 4, 0, 1
    FLOAT4 =             0x03, 4, 'f', 4, 0, 1
    UBYTE4N_COLOR =      0x04, 4, 'B', 1, 1, 0xFF # identical to UBYTE4N
    UBYTE4N_COLOR_ARGB = 0x05, 4, 'B', 1, 1, 1
    UBYTE4N_COLOR_RGBA = 0x06, 4, 'B', 1, 1, 0xFF
    UNDEFINED_0 =        0x07, 0, ' ', 0, 0, 1 # actually the undefined one
    UBYTE2N_COLOR_5650 = 0x08, 4, 'B', 1, 1, 1
    UBYTE2N_COLOR_5551 = 0x09, 4, 'B', 1, 1, 1
    UBYTE2N_COLOR_4444 = 0x0A, 4, 'B', 1, 1, 1
    INT1 =               0x0B, 1, 'i', 4, 0, 0x7FFFFFFF
    INT2 =               0x0C, 2, 'i', 4, 0, 0x7FFFFFFF
    INT4 =               0x0D, 4, 'i', 4, 0, 0x7FFFFFFF
    UINT1 =              0x0E, 1, 'I', 4, 0, 0xFFFFFFFF
    UINT2 =              0x0F, 2, 'I', 4, 0, 0xFFFFFFFF
    UINT4 =              0x10, 4, 'I', 4, 0, 0xFFFFFFFF
    INT1N =              0x11, 1, 'i', 4, 1, 0x7FFFFFFF
    INT2N =              0x12, 2, 'i', 4, 1, 0x7FFFFFFF
    INT4N =              0x13, 4, 'i', 4, 1, 0x7FFFFFFF
    UINT1N =             0x14, 1, 'I', 4, 1, 0xFFFFFFFF
    UINT2N =             0x15, 2, 'I', 4, 1, 0xFFFFFFFF
    UINT4N =             0x16, 4, 'I', 4, 1, 0xFFFFFFFF
    UBYTE4 =             0x17, 4, 'B', 1, 0, 0xFF
    UBYTE4_X4 =          0x18, 4, 'B', 1, 1, 4
    BYTE4 =              0x19, 4, 'b', 1, 0, 0x7F
    UBYTE4N =            0x1A, 4, 'B', 1, 1, 0x7F
    #UNDEFINED_1 =       0x1B, 0, ' ', 0, 1, 1
    BYTE4N =             0x1C, 4, 'b', 1, 1, 0x7F
    SHORT2 =             0x1D, 2, 'h', 2, 0, 0x3FFF # This looks wrong but for some reason it isn't
    SHORT4 =             0x1E, 4, 'h', 2, 0, 0x3FFF # This looks wrong but for some reason it isn't
    USHORT2 =            0x1F, 2, 'H', 2, 0, 0xFFFF
    USHORT4 =            0x20, 4, 'H', 2, 0, 0xFFFF
    SHORT2N =            0x21, 2, 'h', 2, 1, 0x7FFF
    SHORT3N =            0x22, 3, 'h', 2, 1, 0x7FFF
    SHORT4N =            0x23, 4, 'h', 2, 1, 0x7FFF
    USHORT2N =           0x24, 2, 'H', 2, 1, 0xFFFF
    USHORT3N =           0x25, 3, 'H', 2, 1, 0xFFFF
    USHORT4N =           0x26, 4, 'H', 2, 1, 0xFFFF
    #UDEC3 =             0x27, 0, ' ', 0, 0, 1
    #DEC3N =             0x28, 0, ' ', 0, 1, 1
    #DEC3N_S11_11_10 =   0x29, 0, ' ', 0, 1, 1
    HALF2 =              0x2A, 2, 'e', 2, 0, 1
    HALF4 =              0x2B, 4, 'e', 2, 0, 1
    UNUSED =             0x2C, 4, 'f', 4, 0, 1
    BYTE3N =             0x2D, 3, 'b', 1, 1, 0x7F
    SHORT3 =             0x2E, 3, 'h', 2, 0, 0x7FFF
    USHORT3 =            0x2F, 3, 'H', 2, 0, 0xFFFF
    UBYTE4_ENDIAN =      0x30, 4, 'B', 1, 0, 0xFF
    UBYTE4_COLOR =       0x31, 4, 'B', 1, 0, 0xFF
    BYTE3 =              0x32, 3, 'b', 1, 0, 0x7F
    UBYTE2N_COLOR_5650_RGB = 0x33, 4, 'B', 1, 1, 1
    #UDEC3_OES =         0x34, 0, ' ', 0, 0, 1
    #DEC3N_OES =         0x35, 0, ' ', 0, 1, 1
    SHORT4N_EDGE =       0x36, 4, 'h', 2, 1, 0x7FFF # identical to SHORT4N, not in v7
    #MAX =               0x37, 0, ' ', 0, 0, 1
    def __new__(cls, value: int, byte_count: int, char: str, size: int, normalized: bool, n_mask: int):
        member = object.__new__(cls)
        member._value_ = value
        member.dtype = char
        member.byte_count = byte_count # seems to match igVertexElement.count
        member.size = size * byte_count
        member.norm = bool(normalized)
        member.mask = n_mask
        return member


# --- Geometry classes ---

@dataclass(slots=True)
class igVertexElement: # 8B2H
    type_val: int
    stream: int
    _mapToElement: int
    count: int
    usage: int
    usage_index: int
    _packDataOffset: int
    _packTypeAndFracHint: int
    byte_offset: int
    _freq: int
    #_type: int
    #_stream: int
    #_count: int
    #_usage: int
    #_usageIndex: int
    #_offset: int
    def loadVBtoNoeBuf(self, vertexBuffer, stride, vertexCount, sOffset):
        if self._usage in (2, 3, 7, 9, 10): return
        cc, ct, cs, typ, normalize, vertexMax = sscVertexBufferTypes[self._type]
        #assert(cc > (2, 2, -1, -1, 2, 1, 0, -1, 0, -1, -1)[self._usage])
        newStride = 0
        offset = sOffset + self._offset
        packDataType, noeDataType = ('I', noesis.RPGEODATA_UINT) if self._usage == 8 else ('f', noesis.RPGEODATA_FLOAT)
        if self._type in sscVertexUnpackFunctions:
            vertexBuffer = sscVertexUnpackFunctions[self._type](vertexBuffer, vertexCount * stride, stride, offset)
            if self._type == 0x30: # UBYTE4_ENDIAN
                if normalize or self._usage == 5:
                    vertexBuffer = pack(IGZ_ENDIAN_SIGN + '{0}{1}'.format(
                            4 * vertexCount, packDataType),
                        *[b / vertexMax for i in vertexBuffer])
                    newStride = 0x10
            else:
                newStride = 0x10
                assert(self._usage != 8)
        elif self._usage == 0 and self._type == 0x23: # SHORT4N but with scale (superchargersFunkiness)
            vertexBuffer = repack_SHORT4Scale3(vertexBuffer, vertexCount * stride, stride, offset)
            newStride = 0x0C
        elif self._usage == 0 and self._type == 0x2E and vBSizesCount > 0: # SHORT3 but 0x400 scaled (wiiFunkiness)
            vertexBuffer = repack_SHORT4Scale3(vertexBuffer, vertexCount * stride, stride, offset, 0x400)
            newStride = 0x0C
        elif normalize or self._usage == 5 and vertexMax > 1: # TEXCOORD always normalize if not float
            if self._type == 0x18 and self._usage == 5: vertexMax *= 0xFF # UBYTE4_X4
            vertexBuffer = pack(IGZ_ENDIAN_SIGN + '{0}{1}'.format(cc * vertexCount, packDataType),
                *[i / vertexMax for i in unpack_from(IGZ_ENDIAN_SIGN +
                        '{0}{1}{2}x'.format(cc, ct, stride - cc * cs) * vertexCount,
                    vertexBuffer + bytes(stride), offset)])
            newStride = cc * 4
        elif self._usage == 8:
            assert(ct not in ('f', 'e'))
        else: # limit unmodified buffers, so Noesis doesn't load excessive vertices
            vertexBuffer = vertexBuffer[sOffset:sOffset + vertexCount * stride]
        offset = self._offset
        cc = self._count
        if newStride: typ, stride, offset, cc = noeDataType, newStride, 0, newStride // 4

        if self._usage == 0:
            rapi.rpgBindPositionBufferOfs(vertexBuffer, noesis.RPGEODATA_FLOAT, stride, offset)
        elif self._usage == 1 and dLoadNormals:
            rapi.rpgBindNormalBufferOfs(vertexBuffer, typ, stride, offset)
        elif self._usage == 4:
            rapi.rpgBindColorBufferOfs(vertexBuffer, typ, stride, offset, cc)
        elif self._usage == 5:
            rapi.rpgBindUV1BufferOfs(vertexBuffer, typ, stride, offset)
        elif self._usage == 6 and dBuildBones:
            rapi.rpgBindBoneWeightBufferOfs(vertexBuffer, typ, stride, offset, cc)
        elif self._usage == 8 and dBuildBones:
            rapi.rpgBindBoneIndexBufferOfs(vertexBuffer, typ, stride, offset, cc)

class IGZDataAllocator:
    '''Locates raw vertex/index data in the IGZ pure data section.

    Raw VB/IB data is stored sequentially in a data section that contains
    no RVTB objects (typically named System or Bootstrap). Data starts at
    section_offset + chunk_alignment and blocks are ordered by the block
    index stored at object field +0x28.

    Small variable alignment gaps (0-30 bytes) exist between some blocks.
    A scan-based approach probes forward to find the exact start of each
    block by validating the data content.
    '''

    # Max bytes to probe forward when searching for block start
    _MAX_PROBE = 64

    def __init__(self, reader):
        self.reader = reader
        self._data_offsets = {}  # obj.global_offset -> data file offset
        self._compute_data_offsets()

    def _compute_data_offsets(self):
        """Compute where each VB/IB's raw data lives in the file."""
        data_section = self._find_data_section()
        if data_section is None:
            return

        data = self.reader.data

        # Collect VB/IB entries sorted by block index (+0x28)
        entries = []
        for obj in self.reader.objects.values():
            if obj.type_name == 'igVertexBuffer':
                vf = obj.get_ref(0x30)
                stride = vf.read_u32(0x10) if vf else 0
                count = obj.read_u32(0x10)
                entries.append({
                    'kind': 'VB', 'obj': obj, 'count': count,
                    'stride': stride, 'data_size': count * stride,
                    'block_idx': obj.read_u32(0x28),
                })
            elif obj.type_name == 'igIndexBuffer':
                count = obj.read_u32(0x10)
                entries.append({
                    'kind': 'IB', 'obj': obj, 'count': count,
                    'stride': 2, 'data_size': count * 2,
                    'block_idx': obj.read_u32(0x28),
                })
        entries.sort(key=lambda e: e['block_idx'])

        # Walk sequentially through the data section
        pos = data_section.offset + data_section.alignment
        last_vb_count = 0

        for e in entries:
            if e['data_size'] == 0:
                continue

            if e['kind'] == 'VB':
                last_vb_count = e['count']

            # Probe forward to find valid data start
            found = self._probe_block_start(
                data, pos, e['kind'], e['count'], e['stride'],
                last_vb_count)

            if found is not None:
                self._data_offsets[e['obj'].global_offset] = found
                pos = found + e['data_size']
            else:
                # Fallback: tight packing (no gap)
                self._data_offsets[e['obj'].global_offset] = pos
                pos += e['data_size']

    def _probe_block_start(self, data, pos, kind, count, stride, max_vert):
        """Scan forward from pos to find where valid data starts.

        Returns the file offset where valid data begins, or None if not found.
        """
        for probe in range(0, self._MAX_PROBE, 2):
            test = pos + probe
            if kind == 'VB':
                if self._validate_vb(data, test, count, stride):
                    return test
            else:
                if self._validate_ib(data, test, count, max_vert):
                    return test
        return None

    @staticmethod
    def _validate_vb(data, pos, count, stride):
        """Check if vertex buffer data at pos looks valid.

        Validates position floats at first, second, middle and last vertices.
        Also checks normal vectors (at byte offset 12) for approximate unit
        length when stride >= 24, and rejects data that looks like packed
        uint16 index data to avoid false positives at IB/VB boundaries.
        """
        end = pos + count * stride
        if end > len(data):
            return False

        # Check key vertex positions
        check_indices = [0]
        if count > 1:
            check_indices.append(1)
        if count > 4:
            check_indices.append(count // 2)
        if count > 2:
            check_indices.append(count - 1)

        for vi in check_indices:
            off = pos + vi * stride
            f1, f2, f3 = struct.unpack_from('<3f', data, off)
            for f in (f1, f2, f3):
                if math.isnan(f) or math.isinf(f) or abs(f) > 1e15:
                    return False

            # All-zeros first vertex could be alignment padding
            if vi == 0 and f1 == 0 and f2 == 0 and f3 == 0 and count > 1:
                f1b, f2b, f3b = struct.unpack_from('<3f', data, pos + stride)
                for f in (f1b, f2b, f3b):
                    if math.isnan(f) or math.isinf(f) or abs(f) > 1e15:
                        return False

        # Normal vector check: normals at +12 should be approximately unit length
        if stride >= 24 and count >= 2:
            for vi in check_indices:
                if vi == 0 and count <= 1:
                    continue
                off = pos + vi * stride + 12
                n1, n2, n3 = struct.unpack_from('<3f', data, off)
                for n in (n1, n2, n3):
                    if math.isnan(n) or math.isinf(n):
                        return False
                length_sq = n1 * n1 + n2 * n2 + n3 * n3
                if length_sq < 0.25 or length_sq > 2.25:
                    return False

        # Reject data that looks like packed uint16 indices
        if count >= 3 and stride >= 12:
            b0, b1, b2, b3, b4, b5 = data[pos:pos + 6]
            if b1 == 0 and b3 == 0 and b5 == 0:
                idx0 = struct.unpack_from('<H', data, pos)[0]
                idx1 = struct.unpack_from('<H', data, pos + 2)[0]
                idx2 = struct.unpack_from('<H', data, pos + 4)[0]
                if idx0 < 300 and idx1 < 300 and idx2 < 300:
                    return False

        return True

    @staticmethod
    def _validate_ib(data, pos, count, max_vert):
        """Check if index buffer data at pos looks valid."""
        if pos + count * 2 > len(data):
            return False

        if max_vert == 0:
            max_vert = 100000

        # Check first several indices
        check = min(count, 12)
        for j in range(check):
            idx = struct.unpack_from('<H', data, pos + j * 2)[0]
            if idx >= max_vert:
                return False

        # Also check last few indices
        if count > 12:
            for j in range(max(0, count - 3), count):
                idx = struct.unpack_from('<H', data, pos + j * 2)[0]
                if idx >= max_vert:
                    return False

        return True

    def _find_data_section(self):
        """Find the pure data section (no RVTB objects, largest).

        The data section is the chunk that contains no objects from the RVTB
        table. For small files it's typically named 'System', for larger maps
        it's 'Bootstrap'.
        """
        reader = self.reader
        chunks = reader.chunks
        if len(chunks) < 3:
            return None

        # Identify which chunks contain RVTB objects
        sections_with_objects = {0}  # chunk[0] is always fixup
        for encoded_offset in reader.fixups.rvtb:
            global_offset = reader._get_global_offset(encoded_offset)
            for i, c in enumerate(chunks):
                if c.offset <= global_offset < c.offset + c.size:
                    sections_with_objects.add(i)
                    break

        # Pick the largest chunk that has no objects
        best = None
        best_size = 0
        for i, c in enumerate(chunks):
            if i not in sections_with_objects and c.size > best_size:
                best = c
                best_size = c.size

        return best

    def get_data_offset(self, obj):
        """Get the file offset where raw data for a VB or IB starts."""
        return self._data_offsets.get(obj.global_offset)


# The following three functions are a code catastrophy. It's probably better to re-write this from the ground up, completely ignoring these (use Noseis info). We need to use element info to identify Numpy vertex buffers (see other Blender plugins for that).

def parse_vertex_elements(reader, vf_obj):
    """Parse vertex element descriptors from an igVertexFormat object.

    Args:
        reader: IGZReader instance
        vf_obj: IGZObject of type igVertexFormat

    Returns:
        list of igVertexElement (excluding terminator)
    """
    # MemRef control at +0x18: high bit = active, lower bits = data size
    ctrl = vf_obj.read_u32(0x18)
    if not (ctrl & 0x80000000):
        return []

    data_size = ctrl & 0x07FFFFFF  # strip active flag and section bits
    if data_size == 0:
        return []

    # Data pointer at +0x20 (ROFS-resolved)
    data_ref = vf_obj.get_raw_ref(0x20)
    if data_ref is None:
        return []

    if isinstance(data_ref, int):
        data_offset = data_ref
    else:
        data_offset = data_ref.global_offset

    # Each element is 12 bytes
    elem_count = data_size // 12
    elements = []

    for i in range(elem_count):
        off = data_offset + i * 12
        # WIP: There's probably a better way
        if off + 12 > len(reader.data):
            break

        # Skip terminator > WIP: There's probably a better way
        if reader.data[off + 0] == ELEMENT_TERMINATOR_TYPE:
            break

        elements.append(igVertexElement(*reader.data[off:off + 8], *struct.unpack_from('<2H', reader.data, off + 8)))

    return elements


def _read_float_components(data, offset, count):
    """Read 'count' floats from data at offset."""
    return struct.unpack_from(f'<{count}f', data, offset)


def extract_igz_geometry(reader, geom_attr_obj, allocator):
    """Extract geometry data from an IGZ igGeometryAttr into a ParsedGeometry.

    Args:
        reader: IGZReader instance
        geom_attr_obj: IGZObject of type igGeometryAttr
        allocator: IGZDataAllocator for finding raw data offsets

    Returns:
        ParsedGeometry or None
    """
    # Import here to avoid circular dependency
    from igb_blender.scene_graph.sg_geometry import ParsedGeometry

    # Get vertex buffer and index buffer
    vb = geom_attr_obj.get_ref(0x18)
    ib = geom_attr_obj.get_ref(0x20)
    if vb is None or ib is None:
        return None

    # Get vertex format
    vf = vb.get_ref(0x30)
    if vf is None:
        return None

    vert_count = vb.read_u32(0x10)
    idx_count = ib.read_u32(0x10)
    stride = vf.read_u32(0x10)

    # Read prim_type from INDEX buffer at +0x30
    igz_prim = ib.read_u32(0x30)

    if vert_count == 0 or idx_count == 0 or stride == 0:
        return None

    # Get raw data offsets
    vb_data_offset = allocator.get_data_offset(vb)
    ib_data_offset = allocator.get_data_offset(ib)
    if vb_data_offset is None or ib_data_offset is None:
        return None

    # Parse vertex format elements
    elements = parse_vertex_elements(reader, vf)
    if not elements:
        return None

    # Build element lookup by usage
    elem_by_usage = {}
    for elem in elements:
        elem_by_usage[elem.usage] = elem

    geom = ParsedGeometry()
    geom.source_obj = geom_attr_obj
    geom.prim_type = igz_prim

    # Extract vertex data
    data = reader.data
    for v in range(vert_count):
        v_off = vb_data_offset + v * stride

        pos_elem = elem_by_usage.get(VertexUsage.POSITION)
        if pos_elem is not None:
            p = _read_float_components(data, v_off + pos_elem.byte_offset, 3)
            geom.positions.append(p)

        nrm_elem = elem_by_usage.get(VertexUsage.NORMAL)
        if nrm_elem is not None:
            n = _read_float_components(data, v_off + nrm_elem.byte_offset, 3)
            geom.normals.append(n)

        uv_elem = elem_by_usage.get(VertexUsage.TEXCOORD) # UV
        if uv_elem is not None:
            uv = _read_float_components(data, v_off + uv_elem.byte_offset, 2)
            geom.uvs.append(uv)

        color_elem = elem_by_usage.get(VertexUsage.COLOR)
        if color_elem is not None:
            # Color may be stored as RGBA float4 or as packed uint32
            if color_elem.type_val == 2:  # Float3/Float4
                c = _read_float_components(data, v_off + color_elem.byte_offset, 4)
                geom.colors.append(c)
            else:
                # Packed ABGR uint32
                packed = struct.unpack_from('<I', data, v_off + color_elem.byte_offset)[0]
                r = (packed & 0xFF) / 255.0
                g = ((packed >> 8) & 0xFF) / 255.0
                b = ((packed >> 16) & 0xFF) / 255.0
                a = ((packed >> 24) & 0xFF) / 255.0
                geom.colors.append((r, g, b, a))

        bw_elem = elem_by_usage.get(VertexUsage.BLENDWEIGHT)
        if bw_elem is not None:
            w = _read_float_components(data, v_off + bw_elem.byte_offset, 4)
            geom.blend_weights.append(w)

        bi_elem = elem_by_usage.get(VertexUsage.BLENDINDICES)
        if bi_elem is not None:
            bi_raw = struct.unpack_from('<I', data, v_off + bi_elem.byte_offset)[0]
            bi = (bi_raw & 0xFF, (bi_raw >> 8) & 0xFF,
                  (bi_raw >> 16) & 0xFF, (bi_raw >> 24) & 0xFF)
            geom.blend_indices.append(bi)

    # Extract index data (uint16)
    for i in range(idx_count):
        idx = struct.unpack_from('<H', data, ib_data_offset + i * 2)[0]
        geom.indices.append(idx)

    return geom


def walk_igz_scene_graph(reader, allocator):
    """Walk the IGZ scene graph and collect geometry instances with material state.

    The scene graph starts from igSceneInfo._sceneGraph (at +0x28) and follows
    igAttrSet/igGroup/igGeometry nodes via their _childList (igNodeList at +0x38)
    and _attrList (igAttrList at +0x40).

    Material/texture attributes are inherited from parent igAttrSet nodes
    and applied to child igGeometryAttr objects.

    Args:
        reader: IGZReader instance (already parsed)
        allocator: IGZDataAllocator for raw data offsets

    Returns:
        list of dicts, each with:
            'geom': ParsedGeometry
            'transform': tuple of 16 floats (identity by default)
            'material_state': dict with material/texture object references
    """
    results = []

    # Find scene info root
    scene_infos = reader.get_objects_by_type('igSceneInfo')
    if not scene_infos:
        return results

    root = scene_infos[0].get_ref(0x28)
    if root is None:
        return results

    # Identity transform > WIP: Must use Blender tools instead!
    identity = (1, 0, 0, 0,
                0, 1, 0, 0,
                0, 0, 1, 0,
                0, 0, 0, 1)

    _walk_node(reader, allocator, root, identity, {}, results, set())
    return results


def _walk_node(reader, allocator, obj, transform, material_state, results, ancestors):
    """Recursively walk a scene graph node."""
    if obj.global_offset in ancestors:
        return  # Cycle detection

    ancestors.add(obj.global_offset)

    # Copy material state so children can override without affecting siblings.
    # Deep-copy texbind_list to prevent sibling contamination.
    state = dict(material_state)
    if 'texbind_list' in state:
        state['texbind_list'] = list(state['texbind_list'])

    # Collect attributes if this is an igAttrSet or igGeometry
    attrs = _get_attr_list(reader, obj)
    geom_attr = None

    for attr in attrs:
        if attr.type_name == 'igGeometryAttr':
            geom_attr = attr
        elif attr.type_name in ('igMuaMaterialAttr', 'igMaterialAttr'):
            state['material_obj'] = attr
        elif attr.type_name in ('igTextureBindAttr2', 'igTextureBindAttr'):
            # Accumulate ALL texture binds (multi-texturing)
            if 'texbind_list' not in state:
                state['texbind_list'] = []
            state['texbind_list'].append(attr)
            # Keep single texbind_obj for backward compat (last one wins)
            state['texbind_obj'] = attr
        elif attr.type_name == 'igColorAttr':
            state['color_obj'] = attr
        elif attr.type_name in ('igBlendFunctionAttr',):
            state['blend_func_obj'] = attr
        elif attr.type_name in ('igBlendStateAttr',):
            state['blend_state_obj'] = attr
        elif attr.type_name in ('igAlphaStateAttr',):
            state['alpha_state_obj'] = attr
        elif attr.type_name in ('igAlphaFunctionAttr',):
            state['alpha_func_obj'] = attr
        elif attr.type_name in ('igTextureStateAttr',):
            state['tex_state_obj'] = attr
        elif attr.type_name in ('igShaderParametersAttr',):
            state['shader_params_obj'] = attr
        elif attr.type_name in ('igCullFaceAttr',):
            state['cull_face_obj'] = attr
        elif attr.type_name in ('igGlobalColorStateAttr',):
            state['global_color_state_obj'] = attr
        elif attr.type_name in ('igMaterialModeAttr',):
            state['material_mode_obj'] = attr

    # If this node has geometry, extract it
    if geom_attr is not None:
        geom = extract_igz_geometry(reader, geom_attr, allocator)
        if geom is not None:
            results.append({
                'geom': geom,
                'transform': transform,
                'material_state': dict(state),
            })

    # Recurse into children
    children = _get_child_list(reader, obj)
    for child in children:
        _walk_node(reader, allocator, child, transform, state, results, ancestors)

    ancestors.discard(obj.global_offset)


def _get_child_list(reader, obj):
    """Get child nodes from an igGroup/igAttrSet's _childList (igNodeList at +0x38)."""
    children = []

    # Look for igNodeList reference - try +0x38 first (igAttrSet/igGroup child list)
    node_list = obj.get_ref(0x38)
    if node_list is None or node_list.type_name != 'igNodeList':
        # Also check other refs for NodeList
        for fo in sorted(obj.references.keys()):
            ref = obj.get_ref(fo)
            if ref and ref.type_name == 'igNodeList':
                node_list = ref
                break

    if node_list is None:
        return children

    list_count = node_list.read_u32(0x10)
    if list_count == 0:
        return children

    # Data pointer at +0x20
    data_ref = node_list.get_raw_ref(0x20)
    if not isinstance(data_ref, int):
        return children

    for i in range(list_count):
        encoded = struct.unpack_from('<I', reader.data, data_ref + i * 8)[0]
        child_global = reader._get_global_offset(encoded)
        child_obj = reader.objects.get(child_global)
        if child_obj is not None:
            children.append(child_obj)

    return children


def _get_attr_list(reader, obj):
    """Get attributes from an igAttrSet's _attrList (igAttrList at +0x40)."""
    attrs = []

    # Look for igAttrList reference at +0x40
    attr_list = obj.get_ref(0x40)
    if attr_list is None or attr_list.type_name != 'igAttrList':
        # Check other refs
        for fo in sorted(obj.references.keys()):
            ref = obj.get_ref(fo)
            if ref and ref.type_name == 'igAttrList':
                attr_list = ref
                break

    if attr_list is None:
        return attrs

    list_count = attr_list.read_u32(0x10)
    if list_count == 0:
        return attrs

    data_ref = attr_list.get_raw_ref(0x20)
    if not isinstance(data_ref, int):
        return attrs

    for i in range(list_count):
        encoded = struct.unpack_from('<I', reader.data, data_ref + i * 8)[0]
        attr_global = reader._get_global_offset(encoded)
        attr_obj = reader.objects.get(attr_global)
        if attr_obj is not None:
            attrs.append(attr_obj)

    return attrs
