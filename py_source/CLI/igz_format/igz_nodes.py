'''MUA2 nodes for IGZ parsing.

Based on:
https://github.com/NefariousTechSupport/NoesisPlugins/blob/main/fmt_alchemy_igz.py

Resources for the future:
- https://github.com/NefariousTechSupport/igArchiveExtractor/tree/no-msbuild/IGZ
- https://github.com/AdventureT/igModelConverter/tree/master/igModelConverter/src
- https://github.com/NefariousTechSupport/igRewrite8/blob/main/igLibrary/Core/igArkCoreFile.cs
- https://github.com/NefariousTechSupport/NoesisPlugins/blob/main/fmt_alchemy_igb.py

Note: Some processes for 64bit systems couild be read as Q instead of I4x,
which results in the same value, if the value is less than Uint32.Max
(assuming all 64bit systems are little endian).
'''

from dataclasses import dataclass, field, InitVar
from struct import Struct
from typing import Type, Any
from igz_geometry import IgzPrimitive
#from igz_reader import IgzReader
# WIP: change node parsing to avoid having to use IgzReader typing


# --- BASE CLASSES ---

@dataclass
class igNode:
    '''Base class for all Alchemy nodes.'''
    reader: InitVar #[IgzReader]
    TypeIndex: int
    _id: int

@dataclass
class igAttribute:
    '''Base class for all Alchemy attributes.'''
    TypeIndex: int
    _cachedUnitID: int

    def __post_init__(self):
        self._cachedUnitID = self._cachedUnitID & 0xFFFF # unconfirmed

# --- NODES AND ATTRIBUTES ---

@dataclass
class igNamedObject(igNode):
    Name: int|str

    def __post_init__(self, reader):
        self.Name = reader.readString(self.Name)

# New 64bit (unconfirmed): 4/8 + 4 + 4 + 4/8
@dataclass
class igDataList(igNode):
    Count: int
    Capacity: int
    Size: int
    Pointer: int
    #List: tuple[int] = field(init=False, default_factory=tuple)

    #def __post_init__(self, reader):
    #    # unused
    #    self.List = reader.readStruct(Struct(reader.Fmt3264(self.Count)), self.Pointer)

@dataclass
class igObjectList(igDataList):
    List: list[igNode] = field(init=False)

    def __post_init__(self, reader):
        self.List = [reader.processNode(p)
            for p in reader.readStruct(Struct(reader.Fmt3264(self.Count)), self.Pointer)]

@dataclass
class igGroup(igNamedObject):
    # name unconfirmed
    # includes flags and some offset
    _childListPtr: int
    Objects: igObjectList = field(init=False)

    def __post_init__(self, reader):
        self.Name = reader.readString(self.Name)
        #if self._childListPtr:
        self.Objects = reader.processNode(self._childListPtr) # igObjectList

@dataclass
class igIntList(igDataList):
    Integers: tuple[int] = field(init=False, default_factory=tuple)

    def __post_init__(self, reader):
        Integers = reader.read(f'{self.Count}i', self.Pointer)

@dataclass
class igSkeleton2(igNode):
    _boneListSize: int # unconfirmed
    _boneListPtr: int
    _inverseJointArraySize: int
    _inverseJointArrayPtr: int

    def __post_init__(self, reader):
        bones = reader.processNode(self._boneListPtr) # igSkeletonBoneList?
        buf = reader.readMemoryRef(self._inverseJointArrayPtr)
        matrices = np.frombuffer(buf,
                    dtype  = f'{reader._endian_sign}i4',
                    count  = bones.Count * 16,
                    offset = buf.Offset).reshape(bones.Count, 16) # WIP: matrix from buffer in Noesis inverse() is used
        for b in bones.List:
            # b.BlendMatrixIndex == index??
            # b.Name
            # identity Matrix if b.BlendMatrixIndex == -1 else
            # matrices[b.BlendMatrixIndex]
            # b.ParentIndex - 1 # for some reason
            pass
        # WIP: for model and skeleton processing, scan the Noesis plugin for self.models and (model).boneList

igSkeletonBoneList = igObjectList

@dataclass
class igSkeletonBone(igNamedObject):
    ParentIndex: int
    BlendMatrixIndex: int
    _translationX: int #
    _translationY: int # unconfirmed
    _translationZ: int #

    def __post_init__(self, reader):
        self.Name = reader.readString(self._string_index)

@dataclass
class igVertexFormat(igNode):
    _stride: int
    _elementsSize: int
    _elementsPtr: int
    _platformDataSize: int
    _platformDataPtr: int
    # unknown memory ref (v6 and less only)
    #_platform: int # WIP
    # unknown + count??
    #_streamSizesSize: int
    #_streamSizesPtr: int

@dataclass
class igVertexBuffer(igNode):
    _count: int
    _countSize: int # (4) unconfirmed
    _countPtr: int  #
    _TMHNIndex: int
    _vertexFormatPtr: int
    _accessMode: int # unconfirmed, enum (IG_VERTEX_ACCESS: READ_WRITE (0), READ (1), WRITE (2), WRITE_ONCE (3), FREQUENT_UPDATES (4))
    #_packDataSize: int # newer versions?
    #_packDataPtr: int  #
    _vertexCount: int # unconfirmed
    _format: igVertexFormat = field(init=False)

    def __post_init__(self, reader):
        self._format = reader.processNode(self._vertexFormatPtr)
        # actual buffer = reader.TMHN[self._TMHNIndex]
        #count = self._format._elementsSize // 12
        #e = reader.read('8B2H' * count, self._format._elementsPtr )
        #for o1, o2 in zip(range(0, 10 * count, 10), range(10, 10 * count, 10)): igVertexElement(*e[o1:o2])
        # in Noesis plugin: vertexStrides[i] = self._format._stride
        #reader.read(f'{self._format._streamSizesSize // 4}I', self._format._streamSizesPtr ) or (self._format._stride,)

@dataclass
class igIndexBuffer(igNode):
    _count: int
    _countSize: int # (4) unconfirmed
    _countPtr: int  #
    _TMHNIndex: int
    #_unknown3: int
    Primitive: IgzPrimitive|int

    def __post_init__(self, reader):
        self.Primitive = IgzPrimitive(self.Primitive)
        # actual buffer = reader.TMHN[self._TMHNIndex]

@dataclass
class igGraphicsVertexBuffer(igNode):
    _vertexBufferPtr: int

@dataclass
class igGraphicsIndexBuffer(igNode):
    _indexBufferPtr: int

@dataclass
class igGeometry(igGroup):
    _attrListPtr: int

    def __post_init__(self, reader):
        super().__post_init__(reader)
        for a in reader.processNode(self._attrListPtr).List: # igAttrList?
            a._vertexBuffer = reader.processNode(a._vertexBufferPtr)
            # ... WIP
        # WIP: Add mesh, if not added with igGeometryAttr

@dataclass
class igEdgeGeometryAttr(igAttribute):
    # if v. 0x06 or less(???): is mesh (WIP)
    _geometryPtr: int

    def __post_init__(self, reader):
        # super().__post_init__(reader) for _cachedUnitID
        _geometry = reader.processNode(self._geometryPtr) # node name??

@dataclass
class igPS3EdgeGeometry(igObjectList):
    # WIP: PS3 mesh
    _skinnedFlag: int

    def __post_init__(self, reader):
        # inherits from igPS3EdgeGeometrySegmentList (igObjectList<igPS3EdgeGeometrySegment>)
        geometries = [reader.processNode(p) for p in reader.readStruct(Struct(reader.Fmt3264(self.Count)), self.Pointer)]
        for g in geometries:
            #spuConfigInfo = EdgeGeomSpuConfigInfo((*reader.read('8B2HI', g._spuConfigInfoPtr), g._skinMatrixByteOffsets0, g._skinMatrixByteOffsets1, g._skinMatricesSizes0, g._skinMatricesSizes1))
            # g._indicesPtr # need decompressing according to spuConfigInfo.NumIndices
            # g._spuVertices0Ptr
            # g._spuVertices1Ptr
            # g._rsxOnlyVerticesPtr
            _ = EdgeGeometryVertexDescriptor(reader.readMemorySlice(g._spuInputStreamDescs0Ptr, g._spuInputStreamDescs0Size)) # or make the class support IgzBuffer
            _ = EdgeGeometryVertexDescriptor(reader.readMemorySlice(g._spuInputStreamDescs1Ptr, g._spuInputStreamDescs1Size))
            _ = EdgeGeometryVertexDescriptor(reader.readMemorySlice(g._rsxOnlyStreamDescPtr, g._rsxOnlyStreamDescSize))
            unpack_from('>8B2HI', buf.Data, buf.Offset)
            # g._skinIndicesAndWeightsPtr
            # WIP: See Noesis plugin (add info to PS3MeshObject)

@dataclass
class igPS3EdgeGeometrySegment(igNode):
    _spuConfigInfoSize: int
    _spuConfigInfoPtr: int
    _indicesSize: int
    _indicesPtr: int
    #count?
    _spuVertices0Size: int
    _spuVertices0Ptr: int
    _spuVertices1Size: int
    _spuVertices1Ptr: int
    #count+?
    _rsxOnlyVerticesSize: int
    _rsxOnlyVerticesPtr: int
    #?
    _skinMatrixByteOffsets0: int
    _skinMatrixByteOffsets1: int
    _skinMatricesSizes0: int
    _skinMatricesSizes1: int
    #count?
    _skinIndicesAndWeightsSize: int
    _skinIndicesAndWeightsPtr: int
    #count?
    _spuInputStreamDescs0Size: int
    _spuInputStreamDescs0Ptr: int
    _spuInputStreamDescs1Size: int
    _spuInputStreamDescs1Ptr: int
    #count?
    _rsxOnlyStreamDescSize: int
    _rsxOnlyStreamDescPtr: int

@dataclass
class igTransform(igNode):
    pass

@dataclass
class igAttrSet(igGroup):
    reader: InitVar #[IgzReader]
    _attributesPtr: int

    def __post_init__(self, reader):
        super().__post_init__(reader)
        for a in reader.processNode(self._attributesPtr).List: # igAttrList?
            pass

@dataclass
class igBlendMatrixSelect(igAttrSet):
    _boneMapListPtr: int

    def __post_init__(self, reader):
        super().__post_init__(reader)
        _ = reader.processNode(self._boneMapListPtr) # node name??

@dataclass
class igGeometryAttr(igAttribute):
    # is mesh (WIP)
    _vertexBufferPtr: int
    _indexBufferPtr: int

    def __post_init__(self, reader):
        _ = reader.processNode(self._vertexBufferPtr)
        _ = reader.processNode(self._indexBufferPtr)

@dataclass
class igTextureAttr2(igAttribute):
    Hash: int = 0

@dataclass
class igTextureBindAttr2(igAttribute):
    reader: InitVar #[IgzReader]
    _texturePtr: int
    Texture: igTextureAttr2 = field(init=False, default=None)

    def __post_init__(self, reader):
        # super().__post_init__(reader) for _cachedUnitID
        self.Texture = reader.processNode(self._texturePtr) # igTextureAttr2

@dataclass
class igMaterialAttr(igAttribute):
    # Specific material variables can be unpacked here
    pass

@dataclass
class igMuaMaterialAttr(igAttribute):
    pass

@dataclass
class igImage2(igNode):
    pass

@dataclass
class asAnimationDatabase(igNode):
    # is model (WIP)
    _unknown1: int
    _unknown2: int
    _unknown3: int
    _skeletonPtr: int
    _skinPtr: int

    def __post_init__(self, reader):
        _ = reader.processNode(self._skeletonPtr) # igSkeleton2?
        _ = reader.processNode(self._skinPtr) # igSkin?

@dataclass
class igSceneInfo(igNode):
    # is model v7 (or swap force)? (WIP)
    _unknown1: int
    _unknown2: int
    _unknown3: int
    _sceneGraphPtr: int

    def __post_init__(self, reader):
        _ = reader.processNode(self._sceneGraphPtr) # node name?

@dataclass
class igStringRefList(igDataList):
    List: list[str] = field(init=False)

    def __post_init__(self, reader):
        # WIP i - 1??
        self.List = [reader.readString(i - 1) for i in reader.readStruct(Struct(reader.Fmt3264(self.Count)), self.Pointer)]

@dataclass
class igHandleList(igDataList): # usually hash list for root nodes
    List: tuple[int] = field(init=False)

    def __post_init__(self, reader):
        self.List = reader.readStruct(Struct(reader.Fmt3264(self.Count)), self.Pointer)

@dataclass
class igSceneTexturesInfo(igNode):
    pass

@dataclass
class igFxMaterialNode(igNode):
    pass

@dataclass
class igSkeleton2Info(igNode):
    _skeletonListPtr: int

    def __post_init__(self, reader):
        for s in reader.processNode(self._skeletonListPtr).List: # igAnimation2List<nod neame??>
            pass

@dataclass
class igAnimation2Info(igNode):
    _animationListPtr: int

    def __post_init__(self, reader):
        for a in reader.processNode(self._animationListPtr).List: # igAnimation2List<nod neame??>
            pass

@dataclass
class igModelInfo(igNode):
    # is model (WIP)
    _modelDataPtr: int

    def __post_init__(self, reader):
        _modelData = reader.processNode(self._modelDataPtr) # igModelData | WIP

@dataclass
class igModelData(igNamedObject):
    _unknown1: int
    _transformCount: int
    _transformSize: int # & 0x00FFFFFF
    _transformPtr: int
    _transformHierarchyCount: int
    _transformHierarchySize: int # & 0x00FFFFFF
    _transformHierarchyPtr: int
    _drawCallsCount: int
    _drawCallsSize: int # & 0x00FFFFFF
    _drawCallsPtr: int
    _drawCallTransformIndicesCount: int
    _drawCallTransformIndicesSize: int # & 0x00FFFFFF
    _drawCallTransformIndicesPtr: int
    _blendMatrixCount: int
    _blendMatrixSize: int # & 0x00FFFFFF
    _blendMatrixPtr: int
    _blendMatrixIndicesCount: int
    _blendMatrixIndicesSize: int # & 0x00FFFFFF
    _blendMatrixIndicesPtr: int
    # object vectors are slightly different from igDataList

    def __post_init__(self, reader):
        self.Name = reader.readString(self._string_index)
        #_ = reader.readPointerVector(self._transformCount, self._transformPtr)
        #_ = reader.readIntVector(self._transformHierarchyCount, self._transformHierarchyPtr)
        dcs = reader.readPointerVector(self._drawCallsCount, self._drawCallsPtr)
        _ = reader.readIntVector(self._drawCallTransformIndicesCount, self._drawCallTransformIndicesPtr)
        # are blend matrices duplicates?
        bmi = reader.readIntVector(self._blendMatrixIndicesCount, self._blendMatrixIndicesPtr)
        for dc in dcs:
            # add new mesh with materialCount and bone_map_list (below) - WIP: see Noesis plugin for details
            dc = reader.processNode(dc) # igModelDrawCallData?
            bone_map_list = bmi[dc._blendVectorOffset:dc._blendVectorOffset + dc._blendVectorCount]

@dataclass
class igModelDrawCallData(igNamedObject):
    _unknown1: int
    _unknown2: int
    _graphicsVertexBufferPtr: int
    _graphicsIndexBufferPtr: int
    _platformDataPtr: int
    _blendVectorOffset: int
    _blendVectorCount: int

    def __post_init__(self, reader):
        # WIP: Can have multiple vertex buffers, but only one index buffer?
        self.Name = reader.readString(self._string_index) # mesh name
        vb = reader.processNode(self._graphicsVertexBufferPtr)
        #assert reader.TMET[vb.TypeIndex] == 'igGraphicsVertexBuffer'
        vb = reader.processNode(vb._vertexBufferPtr)
        ib = reader.processNode(self._graphicsIndexBufferPtr)
        #assert reader.TMET[vb.TypeIndex] == 'igGraphicsIndexBuffer'
        ib = reader.processNode(ib._indexBufferPtr)
        _platformData = reader.processNode(self._platformDataPtr)

@dataclass
class CGraphicsSkinInfo(igNode):
    # is model (WIP)
    _id: int
    _unknown1: int
    _unknown2: int
    _unknown3: int
    _skeletonPtr: int
    _skinPtr: int
    _boltonsPtr: int
    _animationSkelPtr: int
    # 2 X 3f (vector3 bounds, min, max)

    def __post_init__(self, reader):
        _ = reader.processNode(self._skeletonPtr) # igSkeleton2?
        _ = reader.processNode(self._skinPtr) # igModelInfo?

@dataclass
class Drawable(igNode):
    # is mesh (WIP)
    _geometryPtr: int
    _blendMatrixSet: int # boneMapIndex

    def __post_init__(self, reader):
        _ = reader.processNode(self._geometryPtr) # igGeometry?

@dataclass
class tfbPhysicsModel(igNode):
    _tfbBodyPtr: int

    def __post_init__(self, reader):
        _ = reader.processNode(self._tfbBodyPtr) # tfbPhysicsBody?

@dataclass
class tfbPhysicsCombinerLink(igNode):
    _skeletonPtr: int

    def __post_init__(self, reader):
        _ = reader.processNode(self._skeletonPtr) # igSkeleton2?

@dataclass
class tfbEntityInfo(igNode):
    _drawablesPtr: int

    def __post_init__(self, reader):
        _ = reader.processNode(self._drawablesPtr) # igObjectList<Drawable>?

@dataclass
class tfbRuntimeTechniqueInstance(igNode):
    _geomAttrPtr: int

    def __post_init__(self, reader):
        _ = reader.processNode(self._geomAttrPtr) # igGeometryAttr?

@dataclass
class tfbSpriteInfo(igNode):
    _contextDataInfoPtr: int

    def __post_init__(self, reader):
        _ = reader.processNode(self._contextDataInfoPtr) # node name?

@dataclass
class tfbPhysicsBody(igNode):
    # is model (WIP)
    _combinerPrototypePtr: int
    _entityInfoPtr: int # or other node?
    #if platform == 0x0B: pointers (tfbEntityInfo and self) are mixed up

    def __post_init__(self, reader):
        _ = reader.processNode(self._entityInfoPtr) # tfbBodyEntityInfo?
        _ = reader.processNode(self._combinerPrototypePtr) # tfbPhysicsCombinerLink?

@dataclass
class tfbBodyEntityInfo(tfbEntityInfo):
    _blendMatrixIndexListsPtr: int

    def __post_init__(self, reader):
        _blendMatrixIndexLists = reader.processNode(self._blendMatrixIndexListsPtr)
        for d in reader.processNode(self._drawablesPtr).List: # WIP igObjectList<Drawable> unconfirmed
            boneMap = _blendMatrixIndexLists[d._blendMatrixSet]
            # WIP igIntList unconfirmed, hierarchy unconfirmed
            g = reader.processNode(d._geometryPtr) # igGeometry?
            # WIP: ...

@dataclass
class tfbPhysicsWorld(igNode):
    # is model (WIP)
    _entityInfoPtr: int

    def __post_init__(self, reader):
        _ = reader.processNode(self._entityInfoPtr) # tfbEntityInfo / igSceneInfo in <v7?

@dataclass
class tfbActorInfo(igNode):
    _modelPtr: int

    def __post_init__(self, reader):
        _ = reader.processNode(self._modelPtr) # igModelInfo?

# --- MUA2 Effect Nodes --

@dataclass
class CFxTemplate(igNode):
    # 0x10 bytes unknown
    loopTime: float
    # 2I unknown
    poolID: int = 54
    loopCount: int = 2
    # 3I unknown
    persistLoop: int = 0 #flag
    randLoopTime: int = 0 # flag??
    # Wrong: it's only 0x30 in size (i.e. max. 8 values)
    #__handlePtr: int = 0 # NULL
    #__strRefOff: int = 0 # I or Q? Pointer? WIP: important
    #__hashOrID: int = 0
    #__flag_c: int = 0
    # 3I unknown
    #__flag_d: int = 0
    #__flag_e: int = 0
    #__handlePtr2: int = 0 # ?? NULL
    #__strRefOff2: int = 0 # ??

    # Wrong:
    #def __post_init__(self, reader):
    #    _ = reader.processNode(self._id) # CFxMeshPrimitiveAnimationDataList?

@dataclass
class CFxPrimitiveTemplate(igNode):
    # most likely wrong (_namePtr definitely)
    _namePtr: int

    rqSize: tuple[float]
    rqAlpha: tuple[float]
    rqLength: tuple[float]
    rqOffset: tuple[float]
    rqRotation: tuple[float]
    rqRotationRadius: tuple[float]
    rqChaos: tuple[float]
    rqAttenuation: tuple[float]
    rqStartArc: tuple[float]
    rqEndArc: tuple[float]
    rqSize2: tuple[float]
    rqUVScroll: tuple[float]
    rqUVScale: tuple[float]

    rvOrigin: list[tuple[float]]
    rvVelocity: list[tuple[float]]
    rvAcceleration: list[tuple[float]]
    rvRotationAxis: list[tuple[float]]
    rvOrientAxis: list[tuple[float]]
    rvOrigin2: list[tuple[float]]

    startColor1: int
    startColor2: int
    midColor1: int
    midColor2: int
    endColor1: int
    endColor2: int

    def __init__(self, reader, TI: int, ID: int, ptr: int, *values):
        self.TypeIndex = TI
        self._id = ID
        #tempType = CFxType(ID)
        # WIP: Not _namePtr?
        self._namePtr = ptr
        self._renderfxPtr = values[212:213] # WIP: but not floats... CFxParentRender
        self.rqSize, self.rqAlpha, self.rqLength, self.rqOffset, self.rqRotation, self.rqRotationRadius, self.rqChaos, self.rqAttenuation, self.rqStartArc, self.rqEndArc, self.rqSize2, self.rqUVScroll, self.rqUVScale = (values[i:i + 3] for i in range(0, 13 * 8, 8)) # WIP: 5 "padding" values are important?
        rvs = [values[i:i + 3] for i in range(13 * 8, 28 * 8, 8)]
        self.rvOrigin, self.rvVelocity, self.rvAcceleration, self.rvRotationAxis, self.rvOrientAxis = (rvs[i:i + 3] for i in range(0, 15, 3))
        self.rvOrigin2 = (values[28 * 8:28 * 8 + 3], values[29 * 8:29 * 8 + 3])
        self.startColor1, self.startColor2, self.midColor1, self.midColor2, self.endColor1, self.endColor2 = values[-6:]

@dataclass
class CFxMeshPrimitiveAnimationData(igNode):
    values: tuple[int,float] # most likely rotation, location, scale or matrix (but more likely 10 values)

    def __init__(self, reader, TI: int, ID: int, *values):
        self.TypeIndex = TI
        self._id = ID
        self.values = values

@dataclass
class CHavokRigidBodyInfo(igNode):
    values: tuple[int,float]

    def __init__(self, reader, TI: int, ID: int, *values):
        self.TypeIndex = TI
        self._id = ID
        self.values = values

@dataclass
class CHavokForceInfo(igNode):
    # WIP
    unk0x10: int
    unk0x14: int #1
    force: float #800000
    unk0x1C: float
    unk0x20: float
    unk0x24: float
    unk0x28: float
    unk0x2C: float
    unk0x30: float
    unk0x34: float
    unk0x38: float
    unk0x3C: float
    unk0x40: float
    unk0x44: float
    unk0x48: int # padding?
    unk0x4C: int
    unk0x50: int
    unk0x54: int
    unk0x58: int
    unk0x5C: int


# --- THE DYNAMIC REGISTRY ---

def build_registry(is64bit: bool, endian: str) -> dict[str, tuple[Type[igNode], Struct]]:
    '''Builds the struct layouts based on architecture and endianness.'''

    UINT_3264 = 'Q' if is64bit else 'I'
    #NODE_STRUCT_BASE = endian + UINT_3264
    BASE = f'{endian}2{UINT_3264}' # TypeIndex + StringIndex or unit ID
    MEMORY_REF = f'I{4 if is64bit else 0}x{UINT_3264}' # could be f'2{UINT_3264}' or depend on alignment
    DATA_LIST = Struct(f'{BASE}2I{MEMORY_REF}') # + count + capacity + size + pointer
    GROUP = f'{BASE}{UINT_3264}{"32x" if is64bit else "20x"}{UINT_3264}' # 0x38/0x20 | name + flags/offset? + childListPtr
    GRAPHICS_OBJECT = Struct(f'{BASE}{0 if is64bit else 4}x{UINT_3264}')
    INFO = Struct(f'{BASE}12x{UINT_3264}') # 64bit unconfirmed
    replace_this_size = 8 if is64bit else 4
    #model_data_vector_temp = f'2Q{UINT_3264}' if is64Bit and self.header.Version == 9 f'2I{UINT_3264}'

    registry = {
        'igDataList'              : (igDataList, DATA_LIST),
        #'igDataList'              : (igDataList, Struct(f'{endian}{UINT_3264}II{UINT_3264}{MEMORY_REF}')), probably incorrect
        'igNamedObject'           : (igNamedObject, Struct(f'{BASE}{UINT_3264}')),
        'igObjectList'            : (igObjectList, DATA_LIST),
        'igSkeleton2'             : (igSkeleton2, Struct(f'{BASE}{UINT_3264}{MEMORY_REF}')),
        'igSkeletonBoneList'      : (igSkeletonBoneList, DATA_LIST),
        'igSkeletonBone'          : (igSkeletonBone, Struct(f'{BASE}{UINT_3264}2i3f')),
        'igGraphicsVertexBuffer'  : (igGraphicsVertexBuffer, GRAPHICS_OBJECT),
        'igGraphicsIndexBuffer'   : (igGraphicsIndexBuffer, GRAPHICS_OBJECT),
        # Geo buffer structs in later versions (64/32 bit separation incorrect?):
        #'igVertexBuffer'          : (, Struct(f'{endian}{UINT_3264}2I4{UINT_3264}{0 if is64bit else 4}x{MEMORY_REF}')),
        #'igVertexFormat'          : (, Struct(f'{endian}{UINT_3264}2I{MEMORY_REF * 2}I{36 if is64bit else 16}x{MEMORY_REF}')),
        #'igIndexBuffer'           : (, Struct(f'{endian}{UINT_3264}2I4{UINT_3264}i')),
        # PS3 is 32bit (always?)
        'igPS3EdgeGeometry'       : (igPS3EdgeGeometry, Struct(f'{BASE}{9 if is64bit else 17}xB')),
        'igPS3EdgeGeometrySegment': (igPS3EdgeGeometrySegment, Struct(f'{BASE}{MEMORY_REF * 2}4x{MEMORY_REF * 2}12x{MEMORY_REF}4x4H4x{MEMORY_REF}8x{MEMORY_REF * 2}8x{MEMORY_REF}')),

        # max v. 0x08 - 2014 Skylanders: Trap Team
        'igNodeList'              : (igObjectList, DATA_LIST),
        'igIntList'               : (igIntList, DATA_LIST),
        'igGeometryAttr'          : (igGeometryAttr, Struct(f'{BASE}2{UINT_3264}')),
        'igWiiGeometryAttr'       : (igGeometryAttr, Struct(f'{BASE}2{UINT_3264}')),
        'igEdgeGeometryAttr'      : (igEdgeGeometryAttr, Struct(f'{BASE}8x{UINT_3264}')), # WIP: 64bit unconfirmed
        # v6 + 8
        'igIntListList'           : (igObjectList, DATA_LIST),
        'DrawableList'            : (igObjectList, DATA_LIST),
        'Drawable'                : (Drawable, Struct(f'{BASE}4x{UINT_3264}6xH')), # 64bit unconfirmed
        'tfbPhysicsModel'         : (tfbPhysicsModel, INFO), # WIP: 64bit unconfirmed
        'tfbPhysicsCombinerLink'  : (tfbPhysicsCombinerLink, Struct(f'{BASE}4x{UINT_3264}')), # WIP: 64bit unconfirmed
        'tfbWorldEntityInfo'      : (tfbEntityInfo, INFO), # WIP: 64bit unconfirmed

        # max v. 0x07 - 2013 Skylanders: Swap Force
        'igGroup'                 : (igGroup, Struct(GROUP)), # supported in v8?
        'igAttrList'              : (igObjectList, DATA_LIST), # v5 unconfirmed
        'igAttrSet'               : (igAttrSet, Struct(f'{GROUP}{UINT_3264}')), # WIP: 64bit unconfirmed | v5 unconfirmed
        'igActor2'                : (igGroup, Struct(GROUP)), # WIP: structure unknown
        'igSceneInfo'             : (igSceneInfo, Struct(f'{BASE}4{UINT_3264}')), # 64bit unconfirmed
        'igBlendMatrixSelect'     : (igBlendMatrixSelect, Struct(f'{GROUP}{UINT_3264}140x{UINT_3264}')), # WIP: 64bit unconfirmed (maybe 136x)
        'asAnimationDatabase'     : (asAnimationDatabase, Struct(f'{BASE}4{UINT_3264}')), # v5 unconfirmed
        'igGeometry'              : (igGeometry, Struct(f'{GROUP}')), # v5 unconfirmed
        'igTransform'             : (igGroup, Struct(GROUP)), # v5 unconfirmed
        # igTransform serves the same as a group node, but has a transform matrix:
        # int(?) eg. 25, int(?) eg. 0, igNonRefCountedNodeList pointer, flags? matrix 4x4 (16f)

        # max v. 0x06 - 2012 Skylanders: Giants (64bit unconfirmed)
        'igSpatialNode'           : (igGroup, Struct(GROUP)), # WIP: structure unknown
        'tfbRuntimeTechniqueInstance': (tfbRuntimeTechniqueInstance, Struct(f'{BASE}32x{UINT_3264}')),

        # v. 0x05 - 2011 Skylanders: Spyro's Adventure

        # v. 0x06 - 2012 Skylanders: Giants
        #'igFxMaterialNode'        : (igFxMaterialNode, Struct(f'{endian}{"24x" if is64bit else "16x"}{P}')), #?
        #'tfbSpriteInfo'           : (tfbSpriteInfo, Struct(f'{BASE}200x{UINT_3264}')), # WIP: 64bit unconfirmed
        #'tfbPhysicsBody'          : (tfbPhysicsBody, Struct(f'{BASE}24x2{UINT_3264}')), # WIP: 64bit unconfirmed
        #'tfbBodyEntityInfo'       : (tfbEntityInfo, INFO), # WIP: 64bit unconfirmed
        #'tfbPhysicsWorld'         : (tfbPhysicsWorld, Struct(f'{BASE}24x{UINT_3264}')), # WIP: 64bit unconfirmed
        #'tfbActorInfo'            : (tfbActorInfo, Struct(f'{BASE}212x{UINT_3264}')), # WIP: 64bit unconfirmed
        # Note on 64bit count: they could be 'I' with padding/alignment
        'igVertexBuffer'          : (igVertexBuffer, Struct(f'{BASE}{UINT_3264}{MEMORY_REF}4{UINT_3264}')), # count + count (ref) + buffer (ref) + igVertexFormatPtr + pack data (?) + count
        'igVertexFormat'          : (igVertexFormat, Struct(f'{BASE}{UINT_3264}{MEMORY_REF * 2}')), # v. size + element buf + plat. data (unconfirmed/unimportant/unknown) | + MEMORY_REF (unk) + UINT_3264 (platform)
        'igIndexBuffer'           : (igIndexBuffer, Struct(f'{BASE}{UINT_3264}{MEMORY_REF}{UINT_3264}i')), # count + count (ref) + buffer (ref) + prim (with special high value flag) + same as pack data of igVertexBuffer? + count related + count | 32bit unconfirmed (seemingly 4 byte padding/alignment after buffer ref)
        'igStringRefList'         : (igStringRefList, DATA_LIST),
        'igHandleList'            : (igHandleList, DATA_LIST),
        'igSceneTexturesInfo'     : (igSceneTexturesInfo, Struct(f'{endian}')),
        'igTextureBindAttr2'      : (igTextureBindAttr2, Struct(f'{BASE}4{UINT_3264}')), #unk, unk, attributeID, textureHashPtr
        'igTextureAttr2'          : (igTextureAttr2, Struct(f'{BASE}{"72xQ" if is64bit else "60xQ"}')), # hash
        'igMaterialAttr'          : (igMaterialAttr, Struct(BASE)),
        'igMuaMaterialAttr'       : (igMuaMaterialAttr, Struct(f'{endian}')),
        'igImage2'                : (igImage2, Struct(f'{endian}')),

        # v. 0x07 - 2013 Skylanders: Swap Force
        'igFxMaterialNode'        : (igGroup,  Struct(GROUP)), # WIP: structure unknown
        'igWiiGeometry'           : (igGeometry, Struct(f'{endian}')),

        # v. 0x07 - 2013 Skylanders: Lost Islands
        'igSkeleton2Info'         : (igSkeleton2Info, INFO),
        'igSkeleton2List'         : (igObjectList, DATA_LIST),
        'igAnimation2Info'        : (igAnimation2Info, INFO),
        'igAnimation2List'        : (igObjectList, DATA_LIST),

        # v. 0x08 - 2014 Skylanders: Trap Team (64bit unconfirmed)
        #'igFxMaterialNode'        : (igFxMaterialNode, Struct(f'{endian}')), # duplicate, seems to depend on version
        'tfbSpriteInfo'           : (tfbSpriteInfo, Struct(f'{BASE}208x{UINT_3264}')),
        'tfbPhysicsBody'          : (tfbPhysicsBody, Struct(f'{BASE}32x{UINT_3264}4x{UINT_3264}')), # if platform == 0x0B: f'{BASE}24x{UINT_3264}4x{UINT_3264}'
        'tfbBodyEntityInfo'       : (tfbBodyEntityInfo, Struct(f'{INFO.format}12x{UINT_3264}')),
        'tfbPhysicsWorld'         : (tfbPhysicsWorld, Struct(f'{BASE}32x{UINT_3264}')),
        'tfbActorInfo'            : (tfbActorInfo, Struct(f'{BASE}228x{UINT_3264}')),

        # v. 0x09 - 2015 Skylanders: SuperChargers
        'CGraphicsSkinInfo'       : (CGraphicsSkinInfo, Struct(f'{BASE}7{UINT_3264}')),
        'igModelInfo'             : (igModelInfo, Struct(f'{BASE}{3 * replace_this_size}x{UINT_3264}')),
        'igModelData'             : (igModelData, Struct(f'{BASE}2{UINT_3264}32x18{UINT_3264}')), # named + i3264 + 4f + 4f + 6 * 3 i3264
        'igModelDrawCallData'     : (igModelDrawCallData, Struct(f'{BASE}3{UINT_3264}32x3{UINT_3264}2H')),

        # MUA2 effects (v. 0x06)
        'CFxPrimitiveTemplate'    : (CFxPrimitiveTemplate, Struct(f'{BASE}{UINT_3264}{30 * 8}f6I')),
        'CFxTemplate'             : (CFxTemplate, Struct(f'{BASE}16xf8x2I12x2I60x')),
        'CFxMeshPrimitiveAnimationData': (CFxMeshPrimitiveAnimationData, Struct(f'{BASE}10f{UINT_3264}')), # last value unconfirmed, but definitely int, not float
        'CFxMeshPrimitiveAnimationDataList': (igObjectList, DATA_LIST),
        'CHavokForceInfo'         : (CHavokForceInfo, Struct(f'{BASE}2I12f6I')),
        'CHavokRigidBodyInfo'     : (CHavokRigidBodyInfo, Struct(f'{BASE}8I14f')), # cut from I to f unconfirmed
        #CFxParentRender for renderfx

        # Unreversed nodes:
        # igNonRefCountedNodeList (seemingly 0 content in igGroup pair with igNodeList)
        # igColorAttr (mat.setDiffuseColor, setSpecularColor, setAmbientColor, setEnvColor, ...)
        #  state attributes are a simple boolean (0 or 1) at rel offset 0x18/0x0C
        # igTextureStateAttr
        # igGlobalColorStateAttr
        # igBlendFunctionAttr
        # igBlendStateAttr
        # igAlphaFunctionAttr
        # igAlphaStateAttr
        # igTextureMatrixStateAttr
        # igVertexBlendStateAttr
        # igTransformSequence1_5 (?)
        # igVec3fList
        # igQuaternionfList
        # igLongList
    }
    
    # Map all list variations to the same struct parser
    #list_aliases = ['igNodeList', 'igAttrList', 'DrawableList', 'igSkeleton2List']
    #for alias in list_aliases:
    #    registry[alias] = registry['igObjectList']
        
    return registry