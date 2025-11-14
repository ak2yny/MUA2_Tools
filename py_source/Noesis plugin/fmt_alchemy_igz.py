# https://github.com/NefariousTechSupport/NoesisPlugins/blob/main/fmt_alchemy_igz.py
# by Nefarious, modified by ak2yny.
# Ideas for improvements:
# - More common methods, where known to exist in all versions (or up to v.08)
# - Better common functions, improvement with groups/sets/lists necessary
# - Add missing 64bit seeks, or possibly improve the seeks as often, the pointer is already there (depending on where it was seeked)
# - Possibly add more 0 section parsing (magic)
# Note: Noesis is Python 3.1 and doesn't support Enum (3.4) or dataclasses (3.7)
# more resources: 
    #https://github.com/NefariousTechSupport/igArchiveExtractor/tree/no-msbuild/IGZ
    #https://github.com/AdventureT/igModelConverter/tree/master/igModelConverter/src
    #https://github.com/NefariousTechSupport/igRewrite8/blob/main/igLibrary/Core/igArkCoreFile.cs
    #https://github.com/NefariousTechSupport/NoesisPlugins/blob/main/fmt_alchemy_igb.py

from inc_noesis import *
from struct import pack, unpack_from

#Debug Settings
dFirstObjectOffset = -1  # Offset of the first object to process, -1 means just loop through every object
dAllowWii = False        # whether or not to allow wii models
dLoadAsImage = False      # Load IGZ as pure image (disables options below)
dBuildMeshes = True      # Whether or not to build the meshes, or just parse the file, useful for debugging specific models on trap team or giants
dBuildBones = True       # Whether or not to build the bones
dLoadNormals = True      # Whether or not to load normals
dModelThreshold = 50     # The highest number of models to extract before the user is prompted with which models to extract

# Reading in LE initially, Noesis is Windows and Win is LE
IGZ_ENDIANNESS_SETTER = {
    0x015A4749: NOE_BIGENDIAN,
    0x49475A01: NOE_LITTLEENDIAN
}
IGZ_ENDIANNESS = 0
IGZ_ENDIAN_SIGN = ('<', '>')

IGZ_FU_EXID = 0x44495845
IGZ_FU_EXNM = 0x4D4E5845
IGZ_FU_MTSZ = 0x5A53544D
IGZ_FU_ONAM = 0x4D414E4F
IGZ_FU_REXT = 0x54584552
IGZ_FU_RHND = 0x444E4852
IGZ_FU_RNEX = 0x58454E52
IGZ_FU_ROOT = 0x544F4F52
IGZ_FU_ROFS = 0x53464F52
IGZ_FU_RPID = 0x44495052
IGZ_FU_RSTT = 0x54545352
IGZ_FU_RVTB = 0x42545652
IGZ_FU_TDEP = 0x50454454
IGZ_FU_TMET = 0x54454D54
IGZ_FU_TMHN = 0x4E484D54
IGZ_FU_TSTR = 0x52545354

IGZ_IMG_FORMAT = { # WIP: Wrong, but works; doesn't depend on bitwidth?
    0x883C45B2: noesis.NOESISTEX_DXT1,
    0xB718471E: noesis.NOESISTEX_DXT5,
    0x05ECD805: noesis.NOESISTEX_RGBA32
}
IGZ_IMG_ONLY = False

def registerNoesisTypes():
    igzHandle = noesis.register("Skylanders Superchargers", ".igz;.bld")
    noesis.setHandlerTypeCheck(igzHandle, alchemyigzCheckType)
    if dLoadAsImage:
        noesis.setHandlerLoadRGBA(igzHandle, alchemyigzLoadRGBA)
    else:
        noesis.setHandlerLoadModel(igzHandle, alchemyigzLoadModel)
    noesis.logPopup()
    return 1

def alchemyigzCheckType(data):
    # Read magic to determine endianness
    global IGZ_ENDIANNESS
    IGZ_ENDIANNESS = IGZ_ENDIANNESS_SETTER.get(NoeBitStream(data).readUInt(), -1)
    if IGZ_ENDIANNESS == -1:
        print("Invalid IGZ")
        return 0
    global IGZ_ENDIAN_SIGN
    IGZ_ENDIAN_SIGN = IGZ_ENDIAN_SIGN[IGZ_ENDIANNESS]
    return 1

def alchemyigzLoadRGBA(data, texList):
    return alchemyigzLoadModel(data, texList)

def alchemyigzLoadModel(data, mdlList):
    ctx = rapi.rpgCreateContext()

    bs = NoeBitStream(data, IGZ_ENDIANNESS)
    bs.seek(4, NOESEEK_ABS)
    version = bs.readUInt()

    # ssa = 2011 Skylanders: Spyro's Adventure
    # sg  = 2012 Skylanders: Giants
    # ssf = 2013 Skylanders: Swap Force
    # stt = 2014 Skylanders: Trap Team
    # ssc = 2015 Skylanders: SuperChargers
    if version == 0x05:
        igz = ssaIgzFile(version)
    elif version == 0x06:
        igz = sgIgzFile(version)
    elif version == 0x07:
        igz = ssfIgzFile(version)
    elif version == 0x08:
        igz = sttIgzFile(version)
    elif version == 0x09:
        igz = sscIgzFile(version)
    else:
        raise NotImplementedError("Version", hex(version), "is unsupported.")

    igz.loadFile(bs)

    print("platform:", igz.platform, "| is wii allowed?", dAllowWii)
    if igz.platform == 2 and not dAllowWii:
        raise Exception("Wii Models are not allowed as they are buggy, if you'd like to try them anyways, edit dAllowWii to \"True\" in fmt_alchemy_igz.py and restart Noesis")

    if dLoadAsImage and igz.isImageFile():
        mdlList.extend(igz.textures)
    elif dLoadAsImage or igz.isImageFile():
        return 0
    elif dBuildMeshes:
        igz.buildMeshes(mdlList)

    return 1

## Common code, shared between all versions

class igzFile(object):
    def __init__(self, version):
        rapi.rpgSetOption(noesis.RPGOPT_BIGENDIAN, IGZ_ENDIANNESS)

        self.pointers = []
        #self.pointerIDs = []
        self.stringList = []
        self.metatypes = []
        self.thumbnails = []
        self.version = version

        self.models = []
        self.boneIdList = []
        self.materialCount = 0
        self.textures = []

        self.platform = None
        self.is64Bit = [
            False, # IG_CORE_PLATFORM_DEFAULT
            False, # IG_CORE_PLATFORM_WIN32
            False, # IG_CORE_PLATFORM_WII
            True,  # IG_CORE_PLATFORM_DURANGO
            False, # IG_CORE_PLATFORM_ASPEN
            False, # IG_CORE_PLATFORM_XENON
            False, # IG_CORE_PLATFORM_PS3
            False, # IG_CORE_PLATFORM_OSX
            True,  # IG_CORE_PLATFORM_WIN64
            False, # IG_CORE_PLATFORM_CAFE
            False, # IG_CORE_PLATFORM_RASPI
            False, # IG_CORE_PLATFORM_ANDROID
            True,  # IG_CORE_PLATFORM_ASPEN64
            False, # IG_CORE_PLATFORM_LGTV
            True,  # IG_CORE_PLATFORM_PS4
            False, # IG_CORE_PLATFORM_WP8
            False, # IG_CORE_PLATFORM_LINUX
        ]
        if version < 0x07: # 0x05 unknown
            self.is64Bit = self.is64Bit[:10] + [
                True,  # IG_CORE_PLATFORM_NGP
                False, # IG_CORE_PLATFORM_ANDROID
                False, # IG_CORE_PLATFORM_MARMALADE; IG_CORE_PLATFORM_DEPRECATED on Trap Team 0x08
            ] # plus DURANGO is IG_CORE_PLATFORM_DEPRECATED
        elif version < 0x09:
            self.is64Bit[12] = False # IG_CORE_PLATFORM_MARMALADE

        self.arkRegisteredTypes = None

    def __del__(self):
        self.arkRegisteredTypes = None
        self.is64Bit = None
        self.textures = None

    def loadFile(self, bs):
        bs.seek(8, NOESEEK_ABS)

        typeHash = bs.readUInt()
        if self.version > 0x06:
            self.platform = bs.readUInt()
            numFixups = bs.readUInt()
            bs.seek(0x18, NOESEEK_ABS)
        else:
            bs.seek(0x10, NOESEEK_ABS)

        for i in range(0x20):
            pointer = igzPointer(bs, self.version)
            if pointer == 0x0:
                break
            print("section {0}: offset {1}".format(i, pointer))
            self.pointers.append(pointer)
        #self.pointerIDs.append('igzProperties')
        #for i in bs.readBytes(self.pointers[0] - bs.tell()).strip(b'\x00').split(b'\x00'):
        #    self.pointerIDs.append(i.decode())

        # Fix up sections (strings)
        start = self.pointers[0].Pointer # always 0x800 ?
        if self.version < 0x07:
            # Duplicate IGZ header, starting with IGZ\x01 magic & self.version
            bs.seek(start + 0x08, NOESEEK_ABS)
            self.platform = bs.readUShort()
            bs.seek(0x6, NOESEEK_REL)
            numFixups = bs.readUInt()
            start += 0x1C
        self.is64Bit = self.is64Bit[self.platform] \
            if self.platform < len(self.is64Bit) else False # IG_CORE_PLATFORM_MAX from enum

        for i in range(numFixups):
            bs.seek(start, NOESEEK_ABS)
            magic = bs.readUInt()
            if self.version < 0x07:
                bs.seek(0x08, NOESEEK_REL)
            count = bs.readUInt()
            length = bs.readUInt()
            startContent = start + bs.readUInt()
            bs.seek(startContent, NOESEEK_ABS) # already here

            if magic in (IGZ_FU_TMET, 0):
                for j in range(count):
                    self.metatypes.append(bs.readString())
                    if self.version > 0x07 and bs.tell() % 2 != 0:
                        bs.seek(1, NOESEEK_REL)
                    print('metatypes[0x{0:02X}]: {1}'.format(j, self.metatypes[j]))
            elif magic in (IGZ_FU_TSTR, 1):
                for j in range(count):
                    self.stringList.append(bs.readString())
                    if self.version == 0x09 and bs.tell() % 2 != 0:
                        bs.seek(1, NOESEEK_REL)
                    print('stringList[0x{0:02X}]: {1}'.format(j, self.stringList[j]))
            elif magic in (IGZ_FU_TMHN, 10, 11):
                if len(self.thumbnails) > 0:
                    raise ValueError("Duplicate section found for types TMHN, 10, 11")
                sizeofRef = 0x10 if self.is64Bit else 0x08
                for j in range(count):
                    bs.seek(startContent + j * sizeofRef, NOESEEK_ABS)
                    self.thumbnails.append(self.readMemoryRef(bs))
            elif magic == IGZ_FU_TDEP:
                for j in range(count * 2):
                    print('Dependencies[0x{0:02X}]: {1}'.format(j, bs.readString()))
                    if self.version == 0x09 and bs.tell() % 2 != 0:
                        bs.seek(1, NOESEEK_REL)
            elif magic == IGZ_FU_MTSZ:
                for j in range(count):
                    print('MTSZ[0x{0:02X}]: {1}'.format(j, bs.readUInt()))
            elif magic == IGZ_FU_EXID:
                for j in range(count * 2):
                    print('EXID[0x{0:02X}]: {1}'.format(j, bs.readUInt()))
            elif magic == IGZ_FU_EXNM:
                for j in range(count * 2 * 2):
                    print('Materials[0x{0:02X}]: {1}'.format(j, bs.readUShort()))
                    # each first two are name, second two are dep
            elif magic == IGZ_FU_RVTB:
                for j in range(count + 3):
                    print('RVTB[0x{0:02X}]: {1}'.format(j, bs.readByte()))
            elif magic == IGZ_FU_RSTT:
                for j in range(count + 4):
                    print('RSTT[0x{0:02X}]: {1}'.format(j, bs.readByte()))
                bs.readUInt()
            # elif magic == IGZ_FU_ROFS:
            # elif magic == IGZ_FU_RPID:
            # elif magic == IGZ_FU_REXT:
            # elif magic == IGZ_FU_RHND:
            # elif magic == IGZ_FU_RNEX:
            elif magic == 2: # hashes? (count matches material count or types?)
                for j in range(count): # this is not accurate, but works for now
                    self.textureFormat = IGZ_IMG_FORMAT.get((bs.readUInt64() & 0xFFFFFFFF) if self.is64Bit else bs.readUInt(), '')
            # elif magic == 4: for j in range(min(count, length - 0x18)): bs.readByte()
            # elif magic == 5: for j in range(count): bs.readByte()
            # elif magic == 6: for j in range(min(count, length - 0x18)): bs.readByte()
            # elif magic == 7: for j in range(length - 0x18): bs.readByte() ?
            # elif magic == 8: for j in range(count): bs.readUInt() # 8 in test file
            # elif magic == 9: for j in range(count): root_namesRef = self.process_igDataList(bs, bs.readUInt())
            # elif magic == 12: for j in range(length - 0x18): bs.readByte() or bs.readBytes(count / 10 * 16) ?
            # elif magic == 13: for j in range(count): bs.readUInt(); --bs.readBytes([-1]I)--
            # elif magic == 14: for j in range(count): root_node_namesRef = self.process_igDataList(bs, bs.readUInt())
            # elif magic == 16: for j in range(count + 2): bs.readUShort()
            elif magic == IGZ_FU_ROOT:
                for j in range(count):
                    print('Root ID[0x{0:02X}]: {1}'.format(j, bs.readUInt()))
            elif magic == IGZ_FU_ONAM:
                for j in range(count):
                    print('ONAM ID[0x{0:02X}]: {1}'.format(j, bs.readUInt()))
                # is this where the model would start assert(bs.tell() == start + length)?

            start += length

        if dFirstObjectOffset >= 0:
            self.process_igObject(bs, dFirstObjectOffset)
        else:
            self.process_igObjectList(bs,
                self.pointers[1].aligned if self.pointers[1]._alignment > 0 else # ?
                self.pointers[1].Pointer + (0 if self.version == 0x09 else 4))

    def isImageFile(self) -> bool:
        return len(self.models) == 0 and len(self.textures) > 0

    def addModel(self, ID) -> bool:
        shouldAddModel = not any(model.id == ID for model in self.models)
        if shouldAddModel:
            self.models.append(ModelObject(ID))
            print("Adding model with id", hex(ID), "... added")
        else:
            print("Adding model with id", hex(ID), "... not added (duplicate)")
        return shouldAddModel

    def buildMeshes(self, mdlList):
        # Textures
        # WIP: Textures can also be internal. Unknown how to handle that.
        # WIP: Works for MUA only (external file reference).
        ifn = rapi.getDirForFilePath(rapi.getInputName())
        parent = ifn[:ifn[:-1].rfind('\\') + 1]
        loadedTextures = []
        loadedMaterial = {mi: [] for mi in range(self.materialCount)}
        for stringIndex, (textureType, materialIndex) in enumerate(self.textures):
            if len(self.stringReferences) > 0 and stringIndex < len(self.stringReferences[0]):
                texPath = parent + self.stringList[self.stringReferences[0][stringIndex]]
                if rapi.checkFileExists(texPath):
                    with open(texPath, 'rb') as f:
                        imageStream = NoeBitStream(f.read(), IGZ_ENDIANNESS)
                        imageStream.seek(4, NOESEEK_ABS)
                        version = imageStream.readUInt()
                        if self.version == version and version == 0x06:
                            igzImage = sgIgzFile(version)
                            igzImage.loadFile(imageStream)
                            if igzImage.isImageFile():
                                loadedTextures.append(igzImage.textures[0])
                                loadedMaterial[materialIndex].append((rapi.getExtensionlessName(rapi.getLocalFileName(texPath)), igzImage.textures[0].name, textureType))

        # Models
        startIndex = 0
        numModels = len(self.models)
        if numModels > dModelThreshold:
            startIndex = noesis.userPrompt(noesis.NOEUSERVAL_INT, "Model Start Index", "Type in the index of the first model you want to extract (Highest: {0})".format(numModels - 1))
            numModels = noesis.userPrompt(noesis.NOEUSERVAL_INT, "Model Count", "Type in the number of models you want to extract (Highest: {0})".format(numModels - startIndex))

        for index in range(numModels):
            print("Building model {0} of {1}".format(index + startIndex + 1, numModels))
            if len(self.models[index + startIndex].meshes) > 0:
                mdlList.append(self.models[index+startIndex].build(self.version, index+startIndex, loadedMaterial, loadedTextures))
        rapi.rpgReset()

    def bitAwareSeek(self, bs, baseOffset: int, offset64: int, offset32: int):
        bs.seek(baseOffset + (offset64 if self.is64Bit else offset32), NOESEEK_ABS)

    def fixPointer(self, pointer: int) -> int:
        return -1  if pointer & 0x80000000 else \
               self.pointers[(pointer >> 0x18) + 1] + (pointer & 0x00FFFFFF) \
                   if self.version < 0x07 else \
               self.pointers[(pointer >> 0x1B) + 1] + (pointer & 0x07FFFFFF)

    def readPointer(self, bs) -> int:
        return self.fixPointer(bs.readUInt64() if self.is64Bit else bs.readUInt())

    def readMemoryRef(self, bs) -> tuple:
        size = bs.readUInt() & 0x00FFFFFF
        if self.is64Bit:
            bs.seek(0x04, NOESEEK_REL)
        pointer = self.readPointer(bs)
        if pointer == self.pointers[1]:
            return (0, 0, [])
        bs.seek(pointer, NOESEEK_ABS)
        memory = bs.readBytes(size)
        return size, pointer, memory

    def readMemoryRefHandle(self, bs) -> tuple:
        return self.thumbnails[bs.readUInt64() if self.is64Bit else bs.readUInt()]

    def readVector(self, bs): # -> tuple[int]
        if self.is64Bit and self.version == 0x09:
            count = bs.readUInt64()
            size = bs.readUInt64()
        else:
            count = bs.readUInt()
            size = bs.readUInt()
        pointer = self.readPointer(bs)
        return count, size & 0x00FFFFFF, pointer

    def readObjectVector(self, bs) -> list:
        count, _, offset = self.readVector(bs)
        objects = []
        sizeofPointer = 8 if self.is64Bit else 4
        for i in range(count):
            bs.seek(offset + sizeofPointer * i, NOESEEK_ABS)
            objects.append(self.readPointer(bs))
        return objects

    def readIntVector(self, bs) -> list:
        count, _, offset = self.readVector(bs)
        bs.seek(offset, NOESEEK_ABS)
        return [bs.readInt() for _ in range(count)]

    def readVector3(self, bs) -> NoeVec3:
        return NoeVec3(bs.read(IGZ_ENDIAN_SIGN + '3f'))

    def readString(self, bs) -> str:
        raw = bs.readUInt64() if self.is64Bit else bs.readUInt()
        if raw < len(self.stringList):
            return self.stringList[raw]
        else:
            bs.seek(self.fixPointer(raw), NOESEEK_ABS)
            return bs.readString()

    def process_igObject(self, bs, pointer):
        if pointer <= self.pointers[1]:
            return None
        bs.seek(pointer, NOESEEK_ABS)
        typeIndex = bs.readUInt64() if self.is64Bit else bs.readUInt()

        try:
            metatype = self.metatypes[typeIndex]
        except:
            print("got typeIndex:", hex(typeIndex), "@", hex(pointer))
            return None

        print("processing:", metatype, "@", hex(pointer))

        if metatype in self.arkRegisteredTypes:
            return self.arkRegisteredTypes[metatype](self, bs, pointer)
        else:
            print(metatype, "not implemented")
            return None

    def process_igDataList(self, bs, offset) -> tuple:
        self.bitAwareSeek(bs, offset, 0x0C, 0x08)
        _count    = bs.readUInt()
        _capacity = bs.readUInt64() if self.is64Bit else bs.readUInt()
        _data = self.readMemoryRef(bs)
        return _count, _capacity, _data

    def process_igNamedObject(self, bs, offset) -> str:
        self.bitAwareSeek(bs, offset, 0x10, 0x08)
        return self.readString(bs)

    def process_igObjectList(self, bs, offset) -> list:
        dataList = self.process_igDataList(bs, offset)
        sizeofPointer = 8 if self.is64Bit else 4
        returns = []
        for i in range(dataList[0]):
            # rel. pointers are also in dataList[2][2]
            bs.seek(dataList[2][1] + i * sizeofPointer, NOESEEK_ABS)
            returns.append(self.process_igObject(bs, self.readPointer(bs)))
        return returns

    def process_igIntList(self, bs, offset) -> list:
        dataList = self.process_igDataList(bs, offset)
        bs.seek(dataList[2][1], NOESEEK_ABS)
        return list(bs.read(IGZ_ENDIAN_SIGN + str(dataList[0]) + 'i'))

    def process_igGroup(self, bs, offset): # removed in 0x09 ?
        # includes flags and some offset
        self.bitAwareSeek(bs, offset, 0x38, 0x20)
        _childList = self.process_igObject(bs, self.readPointer(bs))

class igzPointer:
    def __init__(self, bs, version):
        # _unknown: type ID?
        self.Pointer, self.Size, self._alignment, self._offset = bs.read(IGZ_ENDIAN_SIGN + '4I')
        self.aligned = self.Pointer if self._alignment == 0 or version > 0x06 else \
                       self.Pointer + self._offset # (-self.Pointer % self._alignment) # ??
    def __str__(self) -> str:
        return str(hex(self.Pointer))
    def __eq__(self, i) -> bool:
        return self.Pointer == i
    def __gt__(self, i) -> bool:
        return self.Pointer > i
    def __lt__(self, i) -> bool:
        return self.Pointer < i
    def __ge__(self, i) -> bool:
        return self.Pointer >= i
    def __le__(self, i) -> bool:
        return self.Pointer <= i
    def __add__(self, i) -> int:
        return self.Pointer + i
    def __sub__(self, i) -> int:
        return self.Pointer - i

# Possibly use Numpy for calculations
def SHORT4Scale3(data: bytes, dataSize: int, stride: int, offset: int, scaleDef: int):
    for o in range(offset, dataSize, stride):
        *coord, scale = unpack_from(IGZ_ENDIAN_SIGN + '4h', data, o)
        if scaleDef: scale = scaleDef
        yield pack(IGZ_ENDIAN_SIGN + '3f', *(c / scale for c in coord))
def SHORT4Scale4(data: bytes, dataSize: int, stride: int, offset: int):
    for o in range(offset, dataSize, stride):
        *coord, scale = unpack_from(IGZ_ENDIAN_SIGN + '4h', data, o)
        yield pack(IGZ_ENDIAN_SIGN + '4f', *([c / scale for c in coord] + [float(scale)]))

def repack_SHORT4Scale3(data: bytes, dataSize: int, stride: int, offset: int = 0, scaleDef: int = 0) -> bytes:
    return b''.join(SHORT4Scale3(data, dataSize, stride, offset, scaleDef))
def repack_SHORT4Scale4(data: bytes, dataSize: int, stride: int, offset: int = 0) -> bytes:
    return b''.join(SHORT4Scale4(data, dataSize, stride, offset))

def unpack_USHORT1(data: bytes, dataSize: int, stride: int, offset: int = 0) -> tuple:
    return unpack_from(IGZ_ENDIAN_SIGN + ('H{}x'.format(stride - 2) * ((dataSize - offset) // stride)), data, offset)

def repack_UBYTE4_ENDIAN(data: bytes, dataSize: int, stride: int, offset: int = 0) -> bytes:
    return b''.join(data[o + 3:o - 1:-1] for o in range(offset, dataSize, stride))
def repack_UBYTE4N_COLOR_ARGB(data: bytes, dataSize: int, stride: int, offset: int = 0) -> bytes:
    return b''.join(pack(IGZ_ENDIAN_SIGN + '4f',
        *(c / 0xFF for c in (data[o + 1:o + 4] + data[o + 0:o +1])))
        for o in range(offset, dataSize, stride))
def repack_UBYTE2N_COLOR_5650(data: bytes, dataSize: int, stride: int, offset: int = 0) -> bytes:
    return b''.join(pack(IGZ_ENDIAN_SIGN + '4f',
        (c >> 11 & 31) / 31, (c >> 5 & 63) / 63, c / 31, 1.0) # reverse?
        for c in unpack_USHORT1(data, dataSize, stride, offset))
def repack_UBYTE2N_COLOR_5551(data: bytes, dataSize: int, stride: int, offset: int = 0) -> bytes:
    return b''.join(pack(IGZ_ENDIAN_SIGN + '4f',
        (c & 31) / 31, (c >> 5 & 31) / 31, (c >> 10 & 31) / 31, c >> 15)
        for c in unpack_USHORT1(data, dataSize, stride, offset))
def repack_UBYTE2N_COLOR_4444(data: bytes, dataSize: int, stride: int, offset: int = 0) -> bytes:
    return b''.join(pack(IGZ_ENDIAN_SIGN + '4f',
        (c & 15) / 15, (c >> 4 & 15) / 15, (c >> 8 & 15) / 15, (c >> 12 & 15) / 15)
        for c in unpack_USHORT1(data, dataSize, stride, offset))

class EdgeGeometryVertexDescriptor(object):
    def __init__(self, data):
        self.count = 0
        self.vertexStride = 0
        self.elements = []
        if len(data) > 1:
            self.count = data[0]
            self.vertexStride = data[1]
            print("count: ", self.count)
            print("stride:", self.vertexStride)
            for i in range(self.count):
                print("  processing element:", i)
                self.elements.append(EdgeGeometryAttributeBlock(data[(i+1)*0x08:(i+2)*0x08]))

class EdgeGeomSpuConfigInfo(object):
    def __init__(self, data):
        self.flagsAndUniformTableCount = data[0]
        self.commandBufferHoleSize = data[1]
        self.inputVertexFormatId = data[2]
        self.secondaryInputVertexFormatId = data[3]
        self.outputVertexFormatId = data[4]
        self.vertexDeltaFormatId = data[5]
        self.indexesFlavorAndSkinningFlavor = data[6]
        self.skinningMatrixFormat = data[7]
        self.numVertexes, \
        self.numIndexes, \
        self.indexesOffset = unpack_from('>2HI', data, 8)

        # Not part of this struct, but had no where better to put it
        self.skinMatrixOffset0 = 0
        self.skinMatrixOffset1 = 0
        self.skinMatrixSize0 = 0
        self.skinMatrixSize1 = 0

EDGE_GEOM_SKIN_NONE = 0
#EDGE_GEOM_SKIN_NO_SCALING = 1
#EDGE_GEOM_SKIN_UNIFORM_SCALING = 2
#EDGE_GEOM_SKIN_NON_UNIFORM_SCALING = 3
#EDGE_GEOM_SKIN_SINGLE_BONE_NO_SCALING = 4
#EDGE_GEOM_SKIN_SINGLE_BONE_UNIFORM_SCALING = 5
#EDGE_GEOM_SKIN_SINGLE_BONE_NON_UNIFORM_SCALING = 6

class EdgeGeometryAttributeBlock(object):
    def __init__(self, data):
        self.offset = data[0]
        self.format = data[1]           # See Formats section of PS3 Reference
        self.componentCount = data[2]
        self.edgeAttributeId = data[3]  # See Attribute Ids section of PS3 Reference
        self.size = data[4]
        self.vertexProgramSlotIndex = data[5]
        self.fixedBlockOffset = data[6]
        self.padding = data[7]
        assert(IGZ_ENDIANNESS == NOE_BIGENDIAN)
    def unpack(self, vertexBuffer, vertexCount, stride):
        if self.edgeAttributeId == 1 and self.componentCount == 4:
            #if unpack_from('>h', data, offset)[0] == 0:
            #    return pack('>4f' *unpack_SHORT4(data, offset))
            #else:
            return repack_SHORT4Scale4(vertexBuffer, vertexCount * stride, stride)
        return b''.join(self.unpackVertex(vertexBuffer[i:i + stride])
            for i in range(0, vertexCount * stride, stride)
            )
    def unpackVertex(self, data):
        componentSize = 0
        if self.format < 10:
            unpackFunction, componentSize = edgeUnpackFunctions[self.format]
        if unpackFunction == None or self.format > 9:
            print("unimplemented format type:", self.format)
        return b''.join(unpackFunction(data, self.offset + componentSize * i)
            if i < self.componentCount else bytes(4) # 0.0
            if i < 4 else b'\x3F\x80\x00\x00' # 1.0
            for i in range(4))

def edgeUnpack_I16N(data, offset):
    return pack('>f', unpack_from('>h', data, offset)[0] / 0x7FFF)
def edgeUnpack_F32(data, offset):
    return data[offset:offset + 4]
def edgeUnpack_F16(data, offset):
    return pack('>f', unpack_from('>e', data, offset)[0])
def edgeUnpack_U8N(data, offset):
    return pack('>f', data[offset] / 0x7F)
def edgeUnpack_I16(data, offset):
    return pack('>f', float(unpack_from('>h', data, offset)[0]))
def edgeUnpack_X11Y11Z10N(data, offset):
    raw, = unpack_from('>I', data, offset)
    return pack('>3f', ((raw & 0x000007FF) >> 0) / 0x7FF, ((raw & 0x003FF800) >> 11) / 0x7FF, ((raw & 0xFFC00000) >> 22) / 0x3FF)
def edgeUnpack_U8(data, offset):
    return pack('>f', float(data[offset]))
#def edgeUnpack_Fixed(data, offset):
#def edgeUnpack_UnitVector(data, offset):

edgeUnpackFunctions = [
    (None, 0),
    (edgeUnpack_I16N, 2),
    (edgeUnpack_F32, 4),
    (edgeUnpack_F16, 2),
    (edgeUnpack_U8N, 1),
    (edgeUnpack_I16, 2),
    (edgeUnpack_X11Y11Z10N, 4),
    (edgeUnpack_U8, 1),
    (None, 0), #edgeUnpack_FIXED_POINT,
    (None, 0), #edgeUnpack_UNIT_VECTOR,
]

## PS3 REFERENCE

# Formats
#    Short Normalized    = 1
#    Float (Single)      = 2
#    Float (Half)        = 3
#    UByte Normalized    = 4
#    Short               = 5
#    bitwise stuff       = 6
#    UByte               = 7
#    Fixed               = 8
#    Unit Vector         = 9

# Attribute Ids
#    Unknown  = 0
#    Position = 1
#    Normal   = 2
#    Tangent  = 3
#    Binormal = 4
#    UV0      = 5
#    UV1      = 6
#    UV2      = 7
#    UV3      = 8
#    Color    = 9

## END OF PS3 REFERENCE

class PS3MeshObject(object):
    def __init__(self):
        self.vertexBuffers = []
        self.vertexStrides = []
        self.vertexCount = 0
        self.indexBuffer = None
        self.spuConfigInfo = None
        self.vertexElements = []
        self.indexCount = None
        self.boneMapIndex = None
    def getBufferForAttribute(self, attributeId):
        if attributeId == 1 and self.vertexElements[0].count == 0:
            elem = EdgeGeometryAttributeBlock(bytes([0, 2, 3, 1, 0, 0, 0, 0]))
            return elem.unpack(self.vertexBuffers[0], self.vertexCount, 0x0C)
        for i in range(3):
            if self.vertexElements[i].count != 0:
                for elem in self.vertexElements[i].elements:
                    if elem.edgeAttributeId == attributeId:
                        #print("stream:", hex(i), "; attr:", hex(elem.edgeAttributeId), "; offset:", hex(elem.offset), "; format:", hex(elem.format), "; componentCount:", hex(elem.componentCount), "; size:", hex(elem.size), "; vertexProgramSlotIndex:", hex(elem.vertexProgramSlotIndex), "; fixedBlockOffset:", hex(elem.fixedBlockOffset))
                        return elem.unpack(self.vertexBuffers[i], self.vertexCount, self.vertexStrides[i])
        return None

    def getPs3BoneStuff(self):
        skinningFlags = self.spuConfigInfo.indexesFlavorAndSkinningFlavor & 0xF
        if skinningFlags == EDGE_GEOM_SKIN_NONE:
            return

        boneMapOffset0 = self.spuConfigInfo.skinMatrixOffset0 // 0x30
        boneMapOffset1 = self.spuConfigInfo.skinMatrixOffset1 // 0x30
        boneMapSize0 = self.spuConfigInfo.skinMatrixSize0 // 0x30

        vertexCount = self.vertexCount
        #build the buffers
        skinBuffer = self.vertexBuffers[3]
        highestIndex = 0
        if skinningFlags > 3: # single bone
            bwBuffer = [0xFF, 0x00, 0x00, 0x00] * vertexCount
            biBuffer = []
            for i in range(vertexCount):
                biBuffer.extend([skinBuffer[i] + boneMapOffset0, 0x00, 0x00, 0x00])
        else:
            bwBuffer = []
            biBuffer = []
            for i in range(vertexCount):
                for j in range(4):
                    bwBuffer.append(skinBuffer[i*8+j*2+0])

                    boneIndex = skinBuffer[i*8+j*2+1]
                    if boneIndex < boneMapSize0:
                        boneIndex += boneMapOffset0
                    else:
                        boneIndex += boneMapOffset1 - boneMapSize0

                    #print("og:", hex(skinBuffer[i*8+j*2+1]), "; size0:", hex(boneMapSize0), "; offset0:", hex(boneMapOffset0), "; offset1:", hex(boneMapOffset1), "; final:", hex(boneIndex))
                    biBuffer.append(boneIndex)

                    if skinBuffer[i*8+j*2+1] > highestIndex:
                        highestIndex = skinBuffer[i*8+j*2+1]
        return (bwBuffer, biBuffer)

class MeshObject(object):
    def __init__(self, materialIndex):
        self.name = ""
        self.vertexBuffers = []
        self.vertexStrides = []
        self.vertexCount = 0
        self.indexBuffer = None
        self.isPs3 = False
        self.ps3Segments = []
        self.spuConfigInfo = False    #PS3 Exclusive
        self.skipBuild = False
        self.vertexElements = []
        self.vertexStreamS = []
        self.primType = noesis.RPGEO_TRIANGLE
        self.indexCount = 0
        self.boneMapIndex = 0
        self.transformation = None
        self.packData = None
        self.platform = 0
        self.platformData = None
        self.materialIndex = materialIndex

    def buildMesh(self, boneMapList):
        rapi.rpgSetName(self.name)

        if self.vertexCount == 0:
            return

        print("name:           {}".format(self.name))
        print("vertex count:   {}; vertex stride: {}".format(self.vertexCount, hex(self.vertexStrides[0])))
        print("index count:    {}".format(self.indexCount))
        #print("bone map index: {}".format(self.boneMapIndex))

        if dBuildBones and -1 < self.boneMapIndex < len(boneMapList) and len(boneMapList[self.boneMapIndex]) > 0:
            rapi.rpgSetBoneMap(boneMapList[self.boneMapIndex])

        processedElements = [False] * 11
        indexableCount = 0

        for elem in self.vertexElements:
            if elem._type == 0x2C: continue # UNUSED

            if processedElements[elem._usage]: continue
            processedElements[elem._usage] = True

            streamOffset = sum(o + (-o % 0x20) for o in (self.vertexStreamS[i] * self.vertexCount for i in range(elem._stream)))
            #print("Getting bytes for stream from", hex(streamOffset), "to", hex(streamOffset + self.vertexCount * self.vertexStreamS[elem._stream]))
            #print("; ".join("{}: {}".format(k, v) for k, v in elem.__dict__.items()), "; streamOffset:", hex(streamOffset))

            elem.loadVBtoNoeBuf(self.vertexBuffers[0], self.vertexStreamS[elem._stream], self.vertexCount, streamOffset)

        #rapi.rpgClearBufferBinds()
        if self.primType == 'IGZ_TRIANGLE_STRIP':
            indexableCount = sum(1 for e in self.vertexElements if e._usage in (0, 1, 4, 5))
            processedIndicies = 0
            processedBytes = 0
            indexSize = indexableCount * 2 if self.indexCount > 0xFF else indexableCount
            fmt = 'H{}x'.format(indexSize - 2) if self.indexCount > 0xFF else \
                  'B{}x'.format(indexSize - 1)

            # Triangle strip commonly has sections, but with Alchemy's unique section checkers they have to be processed separately
            while processedIndicies < self.indexCount:
                checker, indexCount = unpack_from('>2H', self.indexBuffer, processedBytes)
                if checker != 0x9F:
                    raise RuntimeError("Check failed", hex(processedBytes), "bytes into the buffer")
                # filter out position channel specific indices
                indexBuffer = pack('>{}H'.format(indexCount), *unpack_from('>' + fmt * indexCount, self.indexBuffer, processedBytes + 4)) # always BE?
                processedBytes += 4 + indexSize * indexCount
                processedIndicies += indexCount
                #print("Processed", + hex(processedBytes), "bytes. index size", hex(indexSize))
                rapi.rpgCommitTriangles(indexBuffer, noesis.RPGEODATA_USHORT, indexCount, noesis.RPGEO_TRIANGLE_STRIP, 1)
        else:
            rapi.rpgCommitTriangles(self.indexBuffer, noesis.RPGEODATA_UINT if self.indexCount > 0xFFFF else noesis.RPGEODATA_USHORT, self.indexCount, self.primType, 1)
            #rapi.rpgCommitTriangles(None, noesis.RPGEODATA_USHORT, self.vertexCount, noesis.RPGEO_POINTS, 1)

        rapi.rpgClearBufferBinds()

    def buildPS3Mesh(self, boneMapList, version):
        # Ok so on PS3, there are 3 vertex buffers per igPS3EdgeGeometrySegment, they go as follows
        # _spuVertexes0
        # _spuVertexes1
        # _rsxOnlyVertexes
        rapi.rpgSetName(self.name)

        fakeVertexBuffer = None
        if self.vertexStrides[0] == 0:
            fakeVertexBuffer = self.vertexBuffers[0]
        elif version == 0x09:
            fakeVertexBuffer = self.superchargersFunkiness()

        if fakeVertexBuffer != None:
            rapi.rpgBindPositionBufferOfs(fakeVertexBuffer, noesis.RPGEODATA_FLOAT, 0x0C, 0)

        if dBuildBones and len(boneMapList) > 0:
            self.buildNewPS3BoneStuff(boneMapList)

        print("_rsxOnlyVertexes stride:", hex(self.vertexStrides[2]))

        for i in range(3):
            if self.vertexElements[i].count != 0:
                for elem in self.vertexElements[i].elements:
                    if elem.edgeAttributeId == 1:                # POSITION
                        if self.vertexStrides[i] == 0:
                            fakeVertexBuffer = self.vertexBuffers[i]
                        else:
                            fakeVertexBuffer = self.superchargersFunkiness()
                        rapi.rpgBindPositionBufferOfs(fakeVertexBuffer, noesis.RPGEODATA_FLOAT, 0x0C, 0)
                    #elif elem.edgeAttributeId == 2:                # NORMAL
                    #    print("Normal type", elem.format)
                    #    vNormals = elem.unpack(self.vertexBuffers[i], self.vertexStrides[i])
                    #    rapi.rpgBindNormalBufferOfs(vNormals, noesis.RPGEODATA_FLOAT, 0x0C, 0)
                    #elif elem.edgeAttributeId == 3:                # TANGENT
                    #    vTangents = elem.unpack(self.vertexBuffers[i], self.vertexStrides[i])
                    #    rapi.rpgBindTangentBufferOfs(vTangents, noesis.RPGEODATA_FLOAT, 0x0C, 0)
                    elif elem.edgeAttributeId == 5:                # UV0
                        vUV0 = elem.unpack(self.vertexBuffers[i], self.vertexStrides[i])
                        rapi.rpgBindUV1BufferOfs(vUV0, noesis.RPGEODATA_FLOAT, 0x04 * elem.componentCount, 0x0)
                    elif elem.edgeAttributeId == 6:                # UV1
                        vUV1 = elem.unpack(self.vertexBuffers[i], self.vertexStrides[i])
                        rapi.rpgBindUV2BufferOfs(vUV1, noesis.RPGEODATA_FLOAT, 0x04 * elem.componentCount, 0x0)
                    elif elem.edgeAttributeId == 7:                # UV2
                        vUV2 = elem.unpack(self.vertexBuffers[i], self.vertexStrides[i])
                        rapi.rpgBindUVXBufferOfs(vUV2, noesis.RPGEODATA_FLOAT, 0x04 * elem.componentCount, 3, elem.componentCount, 0x0)
                    elif elem.edgeAttributeId == 8:                # UV3
                        vUV3 = elem.unpack(self.vertexBuffers[i], self.vertexStrides[i])
                        rapi.rpgBindUVXBufferOfs(vUV3, noesis.RPGEODATA_FLOAT, 0x04 * elem.componentCount, 4, elem.componentCount, 0x0)
                    elif elem.edgeAttributeId == 9:                # Color
                        vColor = elem.unpack(self.vertexBuffers[i], self.vertexStrides[i])
                        #rapi.rpgBindColorBufferOfs(fixColours(vColor), noesis.RPGEODATA_FLOAT, 0x04 * elem.componentCount, 0x0, elem.componentCount)
                        rapi.rpgBindColorBufferOfs(vColor, noesis.RPGEODATA_FLOAT, 0x04 * elem.componentCount, 0x0, elem.componentCount)


        if self.indexCount <= 0xFFFF:
            rapi.rpgCommitTriangles(self.indexBuffer, noesis.RPGEODATA_USHORT, self.indexCount, noesis.RPGEO_TRIANGLE, 1)
        else:
            rapi.rpgCommitTriangles(self.indexBuffer, noesis.RPGEODATA_UINT, self.indexCount, noesis.RPGEO_TRIANGLE, 1)

        if self.skipBuild == False:
            rapi.rpgClearBufferBinds()

    def buildPs3MeshNew(self, boneMapList, version):
        rapi.rpgSetName(self.name)

        vertexCount = 0
        for segment in self.ps3Segments:
            vertexCount += segment.vertexCount

        vPositions = self.buildBatchedPS3VertexBuffer(1)
        rapi.rpgBindPositionBufferOfs(vPositions, noesis.RPGEODATA_FLOAT, 0x10, 0x00)

        vUV0 = self.buildBatchedPS3VertexBuffer(5)
        if vUV0 != None:
            rapi.rpgBindUV1BufferOfs(vUV0, noesis.RPGEODATA_FLOAT, 0x10, 0x00)

        vUV1 = self.buildBatchedPS3VertexBuffer(6)
        if vUV1 != None:
            rapi.rpgBindUV2BufferOfs(vUV1, noesis.RPGEODATA_FLOAT, 0x10, 0x00)

        vUV2 = self.buildBatchedPS3VertexBuffer(7)
        if vUV2 != None:
            rapi.rpgBindUVXBufferOfs(vUV2, noesis.RPGEODATA_FLOAT, 0x10, 3, 4, 0x00)

        vUV3 = self.buildBatchedPS3VertexBuffer(8)
        if vUV3 != None:
            rapi.rpgBindUVXBufferOfs(vUV3, noesis.RPGEODATA_FLOAT, 0x10, 4, 4, 0x00)

        vColour = self.buildBatchedPS3VertexBuffer(9)
        if vColour != None:
            rapi.rpgBindColorBufferOfs(vColour, noesis.RPGEODATA_FLOAT, 0x10, 0x00, 4)

        if dBuildBones and -1 < self.boneMapIndex < len(boneMapList) and len(boneMapList[self.boneMapIndex]) > 0:
            rapi.rpgSetBoneMap(boneMapList[self.boneMapIndex])

            boneBuffers = self.buildBatchedPs3BoneBuffers()
            #print(hex(len(boneBuffers[0]) // 4))
            rapi.rpgBindBoneWeightBufferOfs(boneBuffers[0], noesis.RPGEODATA_UBYTE, 0x04, 0x00, 0x04)
            rapi.rpgBindBoneIndexBufferOfs(boneBuffers[1], noesis.RPGEODATA_UBYTE, 0x04, 0x00, 0x04)

        #rapi.rpgCommitTriangles(None, noesis.RPGEODATA_USHORT, len(vPositions) // 0x10, noesis.RPGEO_POINTS, 1)
        indexBuffer = self.buildBatchedPS3IndexBuffer()
        rapi.rpgCommitTriangles(indexBuffer[0], noesis.RPGEODATA_UINT, indexBuffer[1], noesis.RPGEO_TRIANGLE, 1)
        rapi.rpgClearBufferBinds()

    def buildBatchedPS3VertexBuffer(self, attributeId):
        batchedBuffer = []
        valid = False
        for segment in self.ps3Segments:
            unpackedBuffer = segment.getBufferForAttribute(attributeId)
            if unpackedBuffer == None:
                for i in range(segment.vertexCount):
                    batchedBuffer.extend(bytes(pack('>ffff', 0.0, 0.0, 0.0, 1.0)))
            else:
                valid = True
                batchedBuffer.extend(unpackedBuffer)
                #print("unpacking buffer..., vertex count should be", segment.vertexCount)
        if valid:
            #print("valid buffer, got", hex(len(batchedBuffer)))
            return bytes(batchedBuffer)
        else:
            return None

    def buildBatchedPS3IndexBuffer(self):
        batchedBuffer = []
        currentIndex = 0
        indexCount = 0
        for segment in self.ps3Segments:
            for i in range(segment.indexCount):
                index, = unpack_from('>H', segment.indexBuffer, i * 2)
                batchedBuffer.extend(pack('>I', index + currentIndex))
            currentIndex += segment.vertexCount
            indexCount += segment.indexCount
        return (bytes(batchedBuffer), indexCount)

    def buildBatchedPs3BoneBuffers(self):
        bwBuffer = []
        biBuffer = []
        for segment in self.ps3Segments:
            buffers = segment.getPs3BoneStuff()
            bwBuffer.extend(buffers[0])
            biBuffer.extend(buffers[1])
        return (bytes(bwBuffer), bytes(biBuffer))

    def superchargersFunkiness(self):
        return repack_SHORT4Scale3(self.vertexBuffers[0], self.vertexCount * self.vertexStrides[0], self.vertexStrides[0])

    def buildPS3BoneStuff(self, boneMapList):
        skinningFlags = self.spuConfigInfo.indexesFlavorAndSkinningFlavor & 0xF
        if skinningFlags == EDGE_GEOM_SKIN_NONE:
            return

        boneMap = []
        boneMap.extend(boneMapList[self.boneMapIndex][self.spuConfigInfo.skinMatrixOffset0 // 0x30:(self.spuConfigInfo.skinMatrixOffset0+self.spuConfigInfo.skinMatrixSize0) // 0x30])
        boneMap.extend(boneMapList[self.boneMapIndex][self.spuConfigInfo.skinMatrixOffset1 // 0x30:(self.spuConfigInfo.skinMatrixOffset1+self.spuConfigInfo.skinMatrixSize1) // 0x30])
        rapi.rpgSetBoneMap(boneMap)

        vertexCount = self.vertexCount
        #Build the buffers
        highestIndex = 0
        rawBuffer = self.vertexBuffers[3]
        if skinningFlags > 3: # single bone
            bwBuffer = [0xFF] * vertexCount
            biBuffer = rawBuffer
            print("one bone:", skinningFlags)
            rapi.rpgBindBoneWeightBuffer(bytes(bwBuffer), noesis.RPGEODATA_UBYTE, 1, 1)
            rapi.rpgBindBoneIndexBuffer(bytes(biBuffer), noesis.RPGEODATA_UBYTE, 1, 1)
        else:
            bwBuffer = []
            biBuffer = []
            firstIndex = self.spuConfigInfo.skinMatrixOffset0 // 0x30
            for i in range(vertexCount):
                for j in range(4):
                    bwBuffer.append(rawBuffer[i*8+j*2+0])
                    biBuffer.append(rawBuffer[i*8+j*2+1])
                    if rawBuffer[i*8+j*2+1] > highestIndex:
                        highestIndex = rawBuffer[i*8+j*2+1]
            rapi.rpgBindBoneWeightBuffer(bytes(bwBuffer), noesis.RPGEODATA_UBYTE, 4, 4)
            rapi.rpgBindBoneIndexBuffer(bytes(biBuffer), noesis.RPGEODATA_UBYTE, 4, 4)
        print("len(bwBuffer):", hex(len(bwBuffer)), "| len(biBuffer):", hex(len(biBuffer)), "| numVertexes:", self.spuConfigInfo.numVertexes, "| highestIndex:", highestIndex, "| boneMap count:", len(boneMap))

    def buildNewPS3BoneStuff(self, boneMapList):
        skinningFlags = self.spuConfigInfo.indexesFlavorAndSkinningFlavor & 0xF
        if skinningFlags == EDGE_GEOM_SKIN_NONE:
            return

        boneMapSize0 = self.spuConfigInfo.skinMatrixSize0 // 0x30
        boneMapOffset0 = self.spuConfigInfo.skinMatrixOffset0 // 0x30
        boneMapOffset1 = self.spuConfigInfo.skinMatrixOffset1 // 0x30
        boneMapOffsetR = boneMapOffset1 - boneMapSize0
        rapi.rpgSetBoneMap(boneMapList[self.boneMapIndex])

        #build the buffers
        if skinningFlags > 3: # single bone
            bwBuffer = b'\xFF' * self.vertexCount
            biBuffer = bytes(i + boneMapOffset0 for i in self.vertexBuffers[3])
            highestIndex = 0
            rapi.rpgBindBoneWeightBuffer(bwBuffer, noesis.RPGEODATA_UBYTE, 1, 1)
            rapi.rpgBindBoneIndexBuffer(biBuffer, noesis.RPGEODATA_UBYTE, 1, 1)
        else:
            bwBuffer = self.vertexBuffers[3][:self.vertexCount:2]
            biBuffer = self.vertexBuffers[3][1:self.vertexCount:2]
            highestIndex = max(biBuffer)
            biBuffer = bytes(i + (boneMapOffset0 if boneIndex < boneMapSize0 else boneMapOffsetR)
                             for i in self.vertexBuffers[3])
                #print("og:", hex(skinBuffer[i*8+j*2+1]), "; size0:", hex(boneMapSize0), "; offset0:", hex(boneMapOffset0), "; offset1:", hex(boneMapOffset1), "; final:", hex(boneIndex))
            rapi.rpgBindBoneWeightBuffer(bwBuffer, noesis.RPGEODATA_UBYTE, 4, 4)
            rapi.rpgBindBoneIndexBuffer(biBuffer, noesis.RPGEODATA_UBYTE, 4, 4)
        #print("len(bwBuffer):", hex(len(bwBuffer)), "| len(biBuffer):", hex(len(biBuffer)), "| numVertexes:", self.spuConfigInfo.numVertexes, "| highestIndex:", highestIndex, "| boneMap count:", len(boneMapList[self.boneMapIndex]))

    def transform(self, mtx):
        self.transformation = mtx


def fixColours(vcolour):
    count = len(vcolour) // 4
    return pack(IGZ_ENDIAN_SIGN + str(count) + 'f', *[
        rgb / 12.92 if rgb < 0.04045 else ((rgb + 0.055) / 1.055) ** 2.4
        for rgb in unpack_from(IGZ_ENDIAN_SIGN + str(count) + 'f', vcolour)])
#        raw * 12.92 if raw < 0.0031308 else raw ** (1 / 2.4) * 1.055 - 0.055


class ModelObject(object):
    def __init__(self, ID = 0):
        self.meshes = []
        self.boneList = []
        self.boneMatrices = []
        self.boneIdList = []
        self.boneMapList = []
        self.anims = []
        self.id = ID
    def build(self, version: int, modelIndex: int, matList: dict = {}, textures: list = []):
        rapi.rpgReset()
        if len(self.meshes) == 0:
            return NoeModel()
        rapi.rpgSetOption(noesis.RPGOPT_BIGENDIAN, IGZ_ENDIANNESS)
        materials = []
        for m in matList.values():
            if m:
                material = NoeMaterial(m[0][0], '')
                for name, tname, ttype in m:
                    if ttype == 0:
                        material.name = name
                        material.setTexture(tname)
                    elif ttype == 1:
                        material.setNormalTexture(tname)
                    elif ttype == 2:
                        material.setSpecularTexture(tname)
                    else:
                        print("Texture type unhandled:", ttype, "; name:", tname)
                        #material.setSpecularTexture(tname)
                        #material.setOpacityTexture(tname)
                        #material.setBumpTexture(tname)
                        #material.setEnvTexture(tname)
                        #material.setOcclTexture(tname)
                materials.append(material)
        for i, mesh in enumerate(self.meshes):
            print("Building mesh {0} of {1}".format(i + 1, len(self.meshes)))
            if not mesh.name:
                mesh.name = "Mesh_{0}_{1}".format(modelIndex, i)
            if mesh.isPs3:
                mesh.buildPs3MeshNew(self.boneMapList, version)
            else:
                materialName = ''
                for materialName, *_ in matList[mesh.materialIndex]: break
                rapi.rpgSetMaterial(materialName) # maybe set material right before committing triangles?
                mesh.buildMesh(self.boneMapList)
        print("Has {0} bones".format(len(self.boneList)))
        try:
            mdl = rapi.rpgConstructModel()
            mdl.setBones(self.boneList)
            if materials and textures:
                mdl.setModelMaterials(NoeModelMaterials(textures, materials))
            return mdl
        except:
            return NoeModel()

## END OF COMMON CODE

#SuperChargers

class sscIgzFile(igzFile): # 0x09
    def __init__(self, version):
        super().__init__(version)
        self.arkRegisteredTypes = sscarkRegisteredTypes

    def process_CGraphicsSkinInfo(self, bs, offset):
        self.models.append(ModelObject())
        #NOTE: should probably add igInfo
        self.bitAwareSeek(bs, offset, 0x28, 0x14)
        _skeleton = self.process_igObject(bs, self.readPointer(bs))
        self.bitAwareSeek(bs, offset, 0x30, 0x18)
        _skin = self.process_igObject(bs, self.readPointer(bs))
        #self.bitAwareSeek(bs, offset, 0x38, 0x1C)
        #_boltPointIndexArray = self.process_igStringIntHashTable(bs, self.readPointer(bs))
        #self.bitAwareSeek(bs, offset, 0x40, 0x20)
        #_havokSkeleton = self.process_CHavokSkeleton(bs, self.readPointer(bs))
        #self.bitAwareSeek(bs, offset, 0x48, 0x24)
        #_boundsMin = self.process_Vector3f(bs)
        #self.bitAwareSeek(bs, offset, 0x54, 0x30)
        #_boundsMax = self.process_Vector3f(bs)

    def process_igSkeleton2(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x20, 0x10)
        _sz, _offset, _inverseJointArray = self.readMemoryRef(bs)
        #print("_inverseJointArray offset:", hex(_offset))
        #print("_inverseJointArray size:  ", hex(_sz))
        self.models[-1].boneMatrices = _inverseJointArray
        self.bitAwareSeek(bs, offset, 0x18, 0x0C)
        _boneList = self.process_igObject(bs, self.readPointer(bs))

    def process_igSkeletonBoneList(self, bs, offset):
        bones = self.process_igObjectList(bs, offset)

        mtxData = self.models[-1].boneMatrices

        for name, parent_ix, ix, _unk in bones:
            #print("bone_" + str(ix) + "_" + str(parent_ix) + "::" + name + "::" + str(_unk))
            # add +1 to index, because some exporters crash otherwise
            noebone = NoeBone(ix, name,
                          (NoeMat44() if ix == -1 else
                           NoeMat44.fromBytes(mtxData[ix * 0x40:(ix + 1) * 0x40],
                                IGZ_ENDIANNESS).inverse()).toMat43(),
                          None, parent_ix - 1)
            #noebone = NoeBone(ix + 1, "bone"+str(ix), mtx.toMat43(), None, parent_ix)
            self.models[-1].boneList.append(noebone)

    def process_igSkeletonBone(self, bs, offset):
        _name = self.process_igNamedObject(bs, offset)
        self.bitAwareSeek(bs, offset, 0x18, 0x0C)
        _parentIndex = bs.readInt()
        self.bitAwareSeek(bs, offset, 0x1C, 0x10)
        _blendMatrixIndex = bs.readInt()
        self.bitAwareSeek(bs, offset, 0x20, 0x14)
        _translation = self.readVector3(bs)
        return (_name, _parentIndex, _blendMatrixIndex, _translation)

    def process_igModelInfo(self, bs, offset):
        self.models.append(ModelObject())
        self.bitAwareSeek(bs, offset, 0x28, 0x14)
        _modelData = self.process_igObject(bs, self.readPointer(bs))

    def process_igModelData(self, bs, offset):
        #NOTE: should probably add igNamedObject
        #self.bitAwareSeek(bs, offset, 0x20, 0x10)
        #_min = self.process_Vector4f(bs)
        #self.bitAwareSeek(bs, offset, 0x30, 0x20)
        #_max = self.process_Vector4f(bs)
        #NOTE: skipped a lot of metafields
        self.bitAwareSeek(bs, offset, 0x40, 0x30)
        _transforms = self.readObjectVector(bs)
        self.bitAwareSeek(bs, offset, 0x58, 0x3C)
        _transformHeirarchy = self.readIntVector(bs)
        self.bitAwareSeek(bs, offset, 0x70, 0x48)
        _drawCalls = self.readObjectVector(bs)
        self.bitAwareSeek(bs, offset, 0x88, 0x54)
        _drawCallTransformIndices = self.readIntVector(bs)
        self.bitAwareSeek(bs, offset, 0xB8, 0x6C)
        _blendMatrixIndices = self.readIntVector(bs)
        self.models[-1].boneIdList = _blendMatrixIndices
        print("igModelData._drawCalls.count():", hex(len(_drawCalls)), "; transforms:", hex(len(_transforms)))
        for i in range(len(_drawCalls)):
            mesh = MeshObject(self.materialCount)
            mesh.boneMapIndex = len(self.models[-1].boneMapList)
            self.models[-1].meshes.append(mesh)
            #self.models[-1].meshes[-1].transform(bs, _transforms[i])
            self.process_igObject(bs, _drawCalls[i])

    def process_igModelDrawCallData(self, bs, offset):
        _name = self.process_igNamedObject(bs, offset)
        self.bitAwareSeek(bs, offset, 0x48, 0x34)
        _graphicsVertexBuffer = self.process_igObject(bs, self.readPointer(bs))
        self.bitAwareSeek(bs, offset, 0x50, 0x38)
        _graphicsIndexBuffer = self.process_igObject(bs, self.readPointer(bs))
        self.bitAwareSeek(bs, offset, 0x58, 0x3C)
        _platformData = self.process_igObject(bs, self.readPointer(bs))
        self.bitAwareSeek(bs, offset, 0x60, 0x40)
        _blendVectorOffset = bs.readUShort()
        self.bitAwareSeek(bs, offset, 0x62, 0x42)
        _blendVectorCount = bs.readUShort()

        print("_blendVectorOffset:", hex(_blendVectorOffset))
        print("_blendVectorCount :", hex(_blendVectorCount))

        self.models[-1].boneMapList.append(self.models[-1].boneIdList[_blendVectorOffset:_blendVectorOffset + _blendVectorCount])
        self.models[-1].meshes[-1].name = _name

    def process_igGraphicsVertexBuffer(self, bs, offset):
        #NOTE: igGraphicsObject is funny
        self.bitAwareSeek(bs, offset, 0x10, 0x0C)
        _vertexBuffer = self.process_igObject(bs, self.readPointer(bs))

    def process_igGraphicsIndexBuffer(self, bs, offset):
        #NOTE: igGraphicsObject is funny
        self.bitAwareSeek(bs, offset, 0x10, 0x0C)
        _indexBuffer = self.process_igObject(bs, self.readPointer(bs))

    def process_igVertexBuffer(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x0C, 0x08)
        self.models[-1].meshes[-1].vertexCount = bs.readUInt() # _vertexCount
        # + 8/16 bytes (?)
        self.bitAwareSeek(bs, offset, 0x20, 0x14)
        _size, _offset, _data = self.readMemoryRefHandle(bs)
        #print("currentposition:", hex(bs.tell()))
        _format = self.process_igObject(bs, self.readPointer(bs))
        # + 4/0 bytes (?)
        self.bitAwareSeek(bs, offset, 0x30, 0x20)
        _packData = self.readMemoryRef(bs)

        self.models[-1].meshes[-1].vertexBuffers.append(_data)
        self.models[-1].meshes[-1].vertexStrides.append(_format)
        if _packData[0] > 0:
            self.models[-1].meshes[-1].packData = _packData
            print("packData offset:", hex(_packData[1]))
            print("packData size:  ", hex(_packData[0]))

        print("vertexCount:    ", hex(self.models[-1].meshes[-1].vertexCount))
        print("vertex offset:  ", hex(_offset))
        print("vertex buf size:", hex(_size))

    def process_igVertexFormat(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x0C, 0x08)
        _vertexSize = bs.readUInt() # total
        _esize, _, _elements = self.readMemoryRef(bs)
        self.bitAwareSeek(bs, offset, 0x20, 0x14)
        self.models[-1].meshes[-1].platformData = self.readMemoryRef(bs)
        self.bitAwareSeek(bs, offset, 0x30, 0x1C)
        self.models[-1].meshes[-1].platform = bs.readUInt()
        # + 16/32 bytes (?)
        self.bitAwareSeek(bs, offset, 0x58, 0x30)
        _size, _offset, _streams = self.readMemoryRef(bs) # individual
        print("Streams offset is", hex(_offset))
        if _offset == 0:
            self.models[-1].meshes[-1].vertexStreamS.append(_vertexSize)
        else:
            self.models[-1].meshes[-1].vertexStreamS.extend(unpack_from('{}I'.format(_size // 4), _streams))

        if self.models[-1].meshes[-1].platformData[0] > 0:
            print("platformData offset:", hex(self.models[-1].meshes[-1].platformData[1]))
            print("platformData size:", hex(self.models[-1].meshes[-1].platformData[0]))

        self.models[-1].meshes[-1].vertexElements = [igVertexElement(_elements[i:i + 0x0C]) for i in range(0, _esize, 0x0C)]
        return _vertexSize

    def process_igIndexBuffer(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x0C, 0x08)
        self.models[-1].meshes[-1].indexCount = bs.readUInt()
        self.bitAwareSeek(bs, offset, 0x20, 0x14)
        _size, _offset, _data = self.readMemoryRefHandle(bs)
        self.models[-1].meshes[-1].indexBuffer = _data
        self.bitAwareSeek(bs, offset, 0x30, 0x1C)
        primType = bs.readInt()
        if primType == 0:
            primType = noesis.RPGEO_POINTS
        elif primType == 1:
            primType = noesis.RPGEO_TRIANGLE_STRIP
        elif primType == 2:
            primType = noesis.RPGEO_TRIANGLE
        elif primType == 3:
            primType = noesis.RPGEO_TRIANGLE # ?
        elif primType == 4:
            primType = 'IGZ_TRIANGLE_STRIP'
        elif primType == 5:
            primType = noesis.RPGEO_TRIANGLE_FAN
        elif primType == 6:
            primType = noesis.RPGEO_TRIANGLE_QUADS
        else:
            raise NotImplementedError("Primitive type", hex(primType), "is not supported.")
        self.models[-1].meshes[-1].primType = primType

        print("indexCount:    ", hex(self.models[-1].meshes[-1].indexCount))
        print("index offset:  ", hex(_offset))
        print("index buf size:", hex(_size))

    def process_igPS3EdgeGeometry(self, bs, offset):
        geometries = self.process_igObjectList(bs, offset)    # igPS3EdgeGeometry inherits from igPS3EdgeGeometrySegmentList which inherits from igObjectList<igPS3EdgeGeometrySegment>
        bs.seek(offset + 0x19, NOESEEK_ABS)
        _isSkinned = bs.readUByte()

        index = 0
        self.models[-1].meshes[-1].isPs3 = True

        for geom in geometries:
            spuConfigInfo = geom[0]

            print("indexCount:     ", hex(spuConfigInfo.numIndexes))
            print("index offset:   ", hex(geom[1][1]))
            print("index buf size: ", hex(geom[1][0]))
            print("vertexCount:    ", hex(spuConfigInfo.numVertexes))
            print("vertex offset:  ", hex(geom[2][1]))
            print("vertex buf size:", hex(geom[2][0]))

            edgeDecomp = rapi.decompressEdgeIndices(geom[1][2], spuConfigInfo.numIndexes)        # _indexes bytes
            print("decompressed indices")
            for i in range(0, spuConfigInfo.numIndexes): #decompressEdgeIndices returns indices in little-endian, so swap back to big because rpg is in bigendian mode
                edgeDecomp[i*2+1:i*2-1:-1] = edgeDecomp[i*2:i*2+2]

            segment = PS3MeshObject()

            segment.spuConfigInfo = spuConfigInfo
            segment.vertexBuffers.extend([geom[2][2], geom[3][2], geom[4][2], geom[8][2]])
            segment.vertexCount = spuConfigInfo.numVertexes
            segment.vertexStrides.extend([geom[5].vertexStride, geom[6].vertexStride, geom[7].vertexStride])
            segment.indexBuffer = edgeDecomp
            segment.indexCount = spuConfigInfo.numIndexes
            segment.vertexElements.extend([geom[5], geom[6], geom[7]])
            self.models[-1].meshes[-1].ps3Segments.append(segment)
            index += 1

    def process_igPS3EdgeGeometrySegment(self, bs, offset):
        #PS3 likes to have sub sub meshes for some reason so we merge them into one submesh
        bs.seek(offset + 0x08, NOESEEK_ABS)
        _spuConfigInfo = self.readMemoryRef(bs)
        bs.seek(offset + 0x10, NOESEEK_ABS)
        _indexes = self.readMemoryRef(bs)
        bs.seek(offset + 0x1C, NOESEEK_ABS)
        _spuVertexes0 = self.readMemoryRef(bs)
        bs.seek(offset + 0x24, NOESEEK_ABS)
        _spuVertexes1 = self.readMemoryRef(bs)
        bs.seek(offset + 0x38, NOESEEK_ABS)
        _rsxOnlyVertexes = self.readMemoryRef(bs)
        bs.seek(offset + 0x44, NOESEEK_ABS)
        _skinMatrixByteOffsets0 = bs.readUShort()
        _skinMatrixByteOffsets1 = bs.readUShort()
        _skinMatricesSizes0 = bs.readUShort()
        _skinMatricesSizes1 = bs.readUShort()
        bs.seek(offset + 0x50, NOESEEK_ABS)
        _skinIndexesAndWeights = self.readMemoryRef(bs)
        print("_skinIndexesAndWeights Buffer @", hex(_skinIndexesAndWeights[1]))
        print("_spuConfigInfo Buffer @", hex(_spuConfigInfo[1]))
        bs.seek(offset + 0x60, NOESEEK_ABS)
        _spuInputStreamDescs0 = self.readMemoryRef(bs)
        bs.seek(offset + 0x68, NOESEEK_ABS)
        _spuInputStreamDescs1 = self.readMemoryRef(bs)
        bs.seek(offset + 0x78, NOESEEK_ABS)
        _rsxOnlyStreamDesc = self.readMemoryRef(bs)
        spuConfigInfoObject = EdgeGeomSpuConfigInfo(_spuConfigInfo[2])
        spuConfigInfoObject.skinMatrixOffset0 = _skinMatrixByteOffsets0
        spuConfigInfoObject.skinMatrixOffset1 = _skinMatrixByteOffsets1
        spuConfigInfoObject.skinMatrixSize0 = _skinMatricesSizes0
        spuConfigInfoObject.skinMatrixSize1 = _skinMatricesSizes1
        #            0              1          2                3              4                                 5                                                       6                                                 7                                              8
        return (spuConfigInfoObject, _indexes, _spuVertexes0, _spuVertexes1, _rsxOnlyVertexes,  EdgeGeometryVertexDescriptor(_spuInputStreamDescs0[2]), EdgeGeometryVertexDescriptor(_spuInputStreamDescs1[2]), EdgeGeometryVertexDescriptor(_rsxOnlyStreamDesc[2]), _skinIndexesAndWeights)

commonArkRegisteredTypes = {
    "igDataList"              : igzFile.process_igDataList,
    "igNamedObject"           : igzFile.process_igNamedObject,
    "igObjectList"            : igzFile.process_igObjectList,
    "igSkeleton2"             : sscIgzFile.process_igSkeleton2,
    "igSkeletonBoneList"      : sscIgzFile.process_igSkeletonBoneList,
    "igSkeletonBone"          : sscIgzFile.process_igSkeletonBone,
    "igGraphicsVertexBuffer"  : sscIgzFile.process_igGraphicsVertexBuffer,
    "igGraphicsIndexBuffer"   : sscIgzFile.process_igGraphicsIndexBuffer,
    "igVertexBuffer"          : sscIgzFile.process_igVertexBuffer,
    "igVertexFormat"          : sscIgzFile.process_igVertexFormat,
    "igIndexBuffer"           : sscIgzFile.process_igIndexBuffer,
    "igPS3EdgeGeometry"       : sscIgzFile.process_igPS3EdgeGeometry,
    "igPS3EdgeGeometrySegment": sscIgzFile.process_igPS3EdgeGeometrySegment
}
sscarkRegisteredTypes = commonArkRegisteredTypes.copy()
sscarkRegisteredTypes.update({
    "CGraphicsSkinInfo"       : sscIgzFile.process_CGraphicsSkinInfo,
    "igModelInfo"             : sscIgzFile.process_igModelInfo,
    "igModelData"             : sscIgzFile.process_igModelData,
    "igModelDrawCallData"     : sscIgzFile.process_igModelDrawCallData
})

# class IG_VERTEX_USAGE(Enum):
#    POSITION = 0 # IG_VERTEX_USAGE_POSITION
#    NORMAL = 1
#    TANGENT = 2
#    BINORMAL = 3
#    COLOR = 4
#    TEXCOORD = 5
#    BLENDWEIGHT = 6
#    UNUSED_0 = 7
#    BLENDINDICES = 8
#    FOGCOORD = 9
#    PSIZE = 10

class igVertexElement():
    def __init__(self, data):
        self._type = data[0]
        self._stream = data[1]
        self._mapToElement = data[2]
        self._count = data[3]
        self._usage = data[4]
        self._usageIndex = data[5]
        self._packDataOffset = data[6]
        self._packTypeAndFracHint = data[7]
        self._offset, \
        self._freq = unpack_from(IGZ_ENDIAN_SIGN + '2H', data, 8)
    def loadVBtoNoeBuf(self, vertexBuffer, stride, vertexCount, sOffset):
        if self._usage in (2, 3, 7, 9, 10): return
        cc, ct, cs, typ, normalize, vertexMax = sscvertexBufferTypes[self._type]
        #assert(cc > (2, 2, -1, -1, 2, 1, 0, -1, 0, -1, -1)[self._usage])
        newStride = 0
        offset = sOffset + self._offset
        packDataType, noeDataType = ('I', noesis.RPGEODATA_UINT) if self._usage == 8 else ('f', noesis.RPGEODATA_FLOAT)
        if self._type in sscvertexUnpackFunctions:
            vertexBuffer = sscvertexUnpackFunctions[self._type](vertexBuffer, vertexCount * stride, stride, offset)
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

sscvertexUnpackFunctions = {
    0x05: repack_UBYTE4N_COLOR_ARGB,
    0x08: repack_UBYTE2N_COLOR_5650,
    0x09: repack_UBYTE2N_COLOR_5551,
    0x0A: repack_UBYTE2N_COLOR_4444,
    0x2C: repack_SHORT4Scale4,
    0x30: repack_UBYTE4_ENDIAN,
    0x33: repack_UBYTE2N_COLOR_5650#_RGB
}
# WIP: Count seems to match igVertexElement._count
sscvertexBufferTypes = {
    0x00: (1, 'f', 4, noesis.RPGEODATA_FLOAT,    0, 1),          # FLOAT1
    0x01: (2, 'f', 4, noesis.RPGEODATA_FLOAT,    0, 1),          # FLOAT2
    0x02: (3, 'f', 4, noesis.RPGEODATA_FLOAT,    0, 1),          # FLOAT3
    0x03: (4, 'f', 4, noesis.RPGEODATA_FLOAT,    0, 1),          # FLOAT4
    0x04: (4, 'B', 1, noesis.RPGEODATA_UBYTE,    1, 0xFF),       # UBYTE4N_COLOR, identical to UBYTE4N
    0x05: (4, 'B', 1, noesis.RPGEODATA_UBYTE,    1, 1),          # UBYTE4N_COLOR_ARGB
    0x06: (4, 'B', 1, noesis.RPGEODATA_UBYTE,    1, 0xFF),       # UBYTE4N_COLOR_RGBA
    #0x07: (0, '', 0, 0, -1, 0, 1), # UNDEFINED_0 actually the undefined one
    0x08: (4, 'B', 1, noesis.RPGEODATA_UBYTE,    1, 1),          # UBYTE2N_COLOR_5650
    0x09: (4, 'B', 1, noesis.RPGEODATA_UBYTE,    1, 1),          # UBYTE2N_COLOR_5551
    0x0A: (4, 'B', 1, noesis.RPGEODATA_UBYTE,    1, 1),          # UBYTE2N_COLOR_4444
    0x0B: (1, 'i', 4, noesis.RPGEODATA_INT,      0, 0x7FFFFFFF), # INT1
    0x0C: (2, 'i', 4, noesis.RPGEODATA_INT,      0, 0x7FFFFFFF), # INT2
    0x0D: (4, 'i', 4, noesis.RPGEODATA_INT,      0, 0x7FFFFFFF), # INT4
    0x0E: (1, 'I', 4, noesis.RPGEODATA_UINT,     0, 0xFFFFFFFF), # UINT1
    0x0F: (2, 'I', 4, noesis.RPGEODATA_UINT,     0, 0xFFFFFFFF), # UINT2
    0x10: (4, 'I', 4, noesis.RPGEODATA_UINT,     0, 0xFFFFFFFF), # UINT4
    0x11: (1, 'i', 4, noesis.RPGEODATA_INT,      1, 0x7FFFFFFF), # INT1N
    0x12: (2, 'i', 4, noesis.RPGEODATA_INT,      1, 0x7FFFFFFF), # INT2N
    0x13: (4, 'i', 4, noesis.RPGEODATA_INT,      1, 0x7FFFFFFF), # INT4N
    0x14: (1, 'I', 4, noesis.RPGEODATA_UINT,     1, 0xFFFFFFFF), # UINT1N
    0x15: (2, 'I', 4, noesis.RPGEODATA_UINT,     1, 0xFFFFFFFF), # UINT2N
    0x16: (4, 'I', 4, noesis.RPGEODATA_UINT,     1, 0xFFFFFFFF), # UINT4N
    0x17: (4, 'B', 1, noesis.RPGEODATA_UBYTE,    0, 0xFF),       # UBYTE4
    0x18: (4, 'B', 1, noesis.RPGEODATA_UBYTE,    1, 4),          # UBYTE4_X4
    0x19: (4, 'b', 1, noesis.RPGEODATA_BYTE,     0, 0x7F),       # BYTE4
    0x1A: (4, 'B', 1, noesis.RPGEODATA_UBYTE,    1, 0x7F),       # UBYTE4N
    #0x1B: (0, '', 0, 1, -1, 1, 1), # UNDEFINED_1
    0x1C: (4, 'b', 1, noesis.RPGEODATA_BYTE,     1, 0x7F),       # BYTE4N
    0x1D: (2, 'h', 2, noesis.RPGEODATA_SHORT,    0, 0x3FFF),     # SHORT2, This looks wrong but for some reason it isn't
    0x1E: (4, 'h', 2, noesis.RPGEODATA_SHORT,    0, 0x3FFF),     # SHORT4, This looks wrong but for some reason it isn't
    0x1F: (2, 'H', 2, noesis.RPGEODATA_USHORT,   0, 0xFFFF),     # USHORT2
    0x20: (4, 'H', 2, noesis.RPGEODATA_USHORT,   0, 0xFFFF),     # USHORT4
    0x21: (2, 'h', 2, noesis.RPGEODATA_SHORT,    1, 0x7FFF),     # SHORT2N
    0x22: (3, 'h', 2, noesis.RPGEODATA_SHORT,    1, 0x7FFF),     # SHORT3N
    0x23: (4, 'h', 2, noesis.RPGEODATA_SHORT,    1, 0x7FFF),     # SHORT4N
    0x24: (2, 'H', 2, noesis.RPGEODATA_USHORT,   1, 0xFFFF),     # USHORT2N
    0x25: (3, 'H', 2, noesis.RPGEODATA_USHORT,   1, 0xFFFF),     # USHORT3N
    0x26: (4, 'H', 2, noesis.RPGEODATA_USHORT,   1, 0xFFFF),     # USHORT4N
    #0x27: (0, '', 0, -1, 0, 1), # UDEC3
    #0x28: (0, '', 0, -1, 1, 1), # DEC3N
    #0x29: (0, '', 0, -1, 1, 1), # DEC3N_S11_11_10
    0x2A: (2, 'e', 2, noesis.RPGEODATA_HALFFLOAT,0, 1),          # HALF2
    0x2B: (4, 'e', 2, noesis.RPGEODATA_HALFFLOAT,0, 1),          # HALF4
    0x2C: (4, 'f', 4, noesis.RPGEODATA_FLOAT,    0, 1),          # UNUSED
    0x2D: (3, 'b', 1, noesis.RPGEODATA_BYTE,     1, 0x7F),       # BYTE3N
    0x2E: (3, 'h', 2, noesis.RPGEODATA_SHORT,    0, 0x7FFF),     # SHORT3
    0x2F: (3, 'H', 2, noesis.RPGEODATA_USHORT,   0, 0xFFFF),     # USHORT3
    0x30: (4, 'B', 1, noesis.RPGEODATA_UBYTE,    0, 0xFF),       # UBYTE4_ENDIAN
    0x31: (4, 'B', 1, noesis.RPGEODATA_UBYTE,    0, 0xFF),       # UBYTE4_COLOR
    0x32: (3, 'b', 1, noesis.RPGEODATA_BYTE,     0, 0x7F),       # BYTE3
    0x33: (4, 'B', 1, noesis.RPGEODATA_UBYTE,    1, 1),          # UBYTE2N_COLOR_5650_RGB
    #0x34: (0, '', 0, -1, 0, 1), # UDEC3_OES
    #0x35: (0, '', 0, -1, 1, 1), # DEC3N_OES
    0x36: (4, 'h', 2, noesis.RPGEODATA_SHORT,    1, 0x7FFF),     # SHORT4N_EDGE, identical to SHORT4N, not in swap force
    #0x37: (0, '', 0, -1, 0, 0), # MAX
}

class ssfIgzFile(igzFile): # 0x07
    def __init__(self, version):
        super().__init__(version)
        self.arkRegisteredTypes = ssfarkRegisteredTypes

    def process_igSceneInfo(self, bs, offset):
        self.models.append(ModelObject())
        self.bitAwareSeek(bs, offset, 0x00, 0x14)
        _sceneGraph = self.process_igObject(bs, self.readPointer(bs))

    def process_igTransform(self, bs, offset):
        # int (25) + 0
        # pointer to igNonRefCountedNodeList
        # flags?
        self.process_igGroup(bs, offset)
        # matrix 4x4 (16f)

    def process_igFxMaterialNode(self, bs, offset):
        self.process_igGroup(bs, offset)

    def process_igGeometry(self, bs, offset):
        self.process_igGroup(bs, offset)
        self.bitAwareSeek(bs, offset, 0x40, 0x24)
        _mc = len(self.models[-1].meshes)
        _attrList = self.process_igObject(bs, self.readPointer(bs))
        if _mc == len(self.models[-1].meshes):
            self.models[-1].meshes.append(MeshObject(self.materialCount))
        self.models[-1].meshes[-1].boneMapIndex = len(self.models[-1].boneMapList) - 1
        self.models[-1].meshes[-1].name = self.process_igNamedObject(bs, offset)

    def process_igEdgeGeometryAttr(self, bs, offset):
        #self.process_igGroup(bs, offset)
        self.bitAwareSeek(bs, offset, 0x00, 0x10)
        _geometry = self.process_igObject(bs, self.readPointer(bs))

    def process_igGeometryAttr(self, bs, offset):
        self.models[-1].meshes.append(MeshObject(self.materialCount))
        self.bitAwareSeek(bs, offset, 0x18, 0x10)
        _vertexBuffer = self.process_igObject(bs, self.readPointer(bs))
        self.bitAwareSeek(bs, offset, 0x20, 0x14)
        _indexBuffer = self.process_igObject(bs, self.readPointer(bs))

    def process_asAnimationDatabase(self, bs, offset):
        self.models.append(ModelObject())
        self.bitAwareSeek(bs, offset, 0x28, 0x14)
        _skeleton = self.process_igObject(bs, self.readPointer(bs))
        self.bitAwareSeek(bs, offset, 0x30, 0x18)
        _skin = self.process_igObject(bs, self.readPointer(bs))

    def process_igAttrSet(self, bs, offset):
        self.process_igGroup(bs, offset)
        self.bitAwareSeek(bs, offset, 0x40, 0x24) # 64 unconfirmed
        _attributes = self.process_igObject(bs, self.readPointer(bs))

    def process_igBlendMatrixSelect(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0xD0, 0xB4) # 64 unconfirmed
        self.models[-1].boneMapList.append(self.process_igObject(bs, self.readPointer(bs)))
        ssfIgzFile.process_igAttrSet(self, bs, offset)

    def process_igAnimation2Info(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x00, 0x14)
        _animationList = self.process_igObject(bs, self.readPointer(bs))

    def process_igSkeleton2Info(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x00, 0x14)
        _skeletonList = self.process_igObject(bs, self.readPointer(bs))

ssfarkRegisteredTypes = commonArkRegisteredTypes.copy()
ssfarkRegisteredTypes.update({
    "igGroup"            : igzFile.process_igGroup,
    "igActor2"           : igzFile.process_igGroup,
    "igIntList"          : igzFile.process_igIntList,
    "igNodeList"         : ssfIgzFile.process_igObjectList,
    "igEdgeGeometryAttr" : ssfIgzFile.process_igEdgeGeometryAttr,
    "igGeometryAttr"     : ssfIgzFile.process_igGeometryAttr,
    "igWiiGeometryAttr"  : ssfIgzFile.process_igGeometryAttr,
    "igFxMaterialNode"   : ssfIgzFile.process_igFxMaterialNode,
    "igSceneInfo"        : ssfIgzFile.process_igSceneInfo,
    "igTransform"        : ssfIgzFile.process_igTransform,
    "igGeometry"         : ssfIgzFile.process_igGeometry,
    "igWiiGeometry"      : ssfIgzFile.process_igGeometry,
    "igAttrList"         : ssfIgzFile.process_igObjectList,
    "asAnimationDatabase": ssfIgzFile.process_asAnimationDatabase,
    "igAttrSet"          : ssfIgzFile.process_igAttrSet,
    "igBlendMatrixSelect": ssfIgzFile.process_igBlendMatrixSelect,

    #Lost Islands Exclusive Types

    "igSkeleton2Info"    : ssfIgzFile.process_igSkeleton2Info,
    "igSkeleton2List"    : ssfIgzFile.process_igObjectList,
    "igAnimation2Info"   : ssfIgzFile.process_igAnimation2Info,
    "igAnimation2List"   : ssfIgzFile.process_igObjectList
})

class sttIgzFile(igzFile): # 0x08
    def __init__(self, version):
        super().__init__(version)
        self.arkRegisteredTypes = sttarkRegisteredTypes

    def process_tfbSpriteInfo(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x00, 0xD8)
        _contextDataInfo = self.process_igObject(bs, self.readPointer(bs))

    def process_tfbPhysicsModel(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x00, 0x14)
        _tfbBody = self.process_igObject(bs, self.readPointer(bs))

    def process_tfbPhysicsBody(self, bs, offset):
        isModelNew = self.addModel(offset)
        if isModelNew:
            self.bitAwareSeek(bs, offset, 0x00, 0x28)
            _combinerPrototype = self.process_igObject(bs, self.readPointer(bs))
            if self.platform == 0x0B:
                bs.seek(offset + 0x20, NOESEEK_ABS)
            else:
                self.bitAwareSeek(bs, offset, 0x00, 0x30)
            _entityInfo = self.process_igObject(bs, self.readPointer(bs))

    def process_tfbBodyEntityInfo(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x00, 0x24)
        _blendMatrixIndexLists = self.process_igObject(bs, self.readPointer(bs))
        if _blendMatrixIndexLists != None:
            print("boneMpaList length is", hex(len(_blendMatrixIndexLists)))
            self.models[-1].boneMapList.extend(_blendMatrixIndexLists)
        sttIgzFile.process_tfbEntityInfo(self, bs, offset)

    def process_tfbEntityInfo(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x00, 0x14)
        _drawables = self.process_igObject(bs, self.readPointer(bs))

    def process_Drawable(self, bs, offset):
        self.models[-1].meshes.append(MeshObject(self.materialCount))
        self.bitAwareSeek(bs, offset, 0x00, 0x16)
        _blendMatrixSet = bs.readUShort()
        self.models[-1].meshes[-1].boneMapIndex = _blendMatrixSet

        self.bitAwareSeek(bs, offset, 0x00, 0x0C)
        _geometry = self.process_igObject(bs, self.readPointer(bs))

    def process_tfbPhysicsWorld(self, bs, offset):
        self.addModel(offset)
        self.bitAwareSeek(bs, offset, 0x00, 0x28)
        _entityInfo = self.process_igObject(bs, self.readPointer(bs))

    def process_tfbPhysicsCombinerLink(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x00, 0x0C)
        _skeleton = self.process_igObject(bs, self.readPointer(bs))

    def process_tfbActorInfo(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x00, 0xEC)
        _model = self.process_igObject(bs, self.readPointer(bs))

sttarkRegisteredTypes = commonArkRegisteredTypes.copy()
sttarkRegisteredTypes.update({
    "igIntList"             : igzFile.process_igIntList,
    "igIntListList"         : igzFile.process_igObjectList, # ?
    "igNodeList"            : ssfIgzFile.process_igObjectList,
    "igEdgeGeometryAttr"    : ssfIgzFile.process_igEdgeGeometryAttr,
    "igGeometryAttr"        : ssfIgzFile.process_igGeometryAttr,
    "igWiiGeometryAttr"     : ssfIgzFile.process_igGeometryAttr,
    "igFxMaterialNode"      : igzFile.process_igGroup, # different
    "DrawableList"          : sttIgzFile.process_igObjectList,
    "Drawable"              : sttIgzFile.process_Drawable,
    "tfbSpriteInfo"         : sttIgzFile.process_tfbSpriteInfo,
    "tfbPhysicsModel"       : sttIgzFile.process_tfbPhysicsModel,
    "tfbPhysicsBody"        : sttIgzFile.process_tfbPhysicsBody,
    "tfbBodyEntityInfo"     : sttIgzFile.process_tfbBodyEntityInfo,
    "tfbPhysicsWorld"       : sttIgzFile.process_tfbPhysicsWorld,
    "tfbPhysicsCombinerLink": sttIgzFile.process_tfbPhysicsCombinerLink,
    "tfbWorldEntityInfo"    : sttIgzFile.process_tfbEntityInfo,
    "tfbActorInfo"          : sttIgzFile.process_tfbActorInfo
})

class sgIgzFile(igzFile): # 0x06
    def __init__(self, version):
        super().__init__(version)
        self.stringReferences = []
        self.arkRegisteredTypes = sgarkRegisteredTypes

    # Maybe this igDataList processor is the correct version, but it was only tested on Win64 v6 files
    def process_igDataList(self, bs, offset) -> tuple:
        self.bitAwareSeek(bs, offset, 0x10, 0x08)
        _count    = bs.readUInt()
        _capacity = bs.readUInt()
        #self.bitAwareSeek(bs, pointer.aligned, 0x18, 0x10) # here already
        return _count, _capacity, self.readMemoryRef(bs)

    def process_igIntList(self, bs, offset) -> tuple:
        dataList = self.process_igDataList(bs, offset)
        bs.seek(dataList[2][1], NOESEEK_ABS)
        return bs.read(IGZ_ENDIAN_SIGN + str(dataList[0]) + 'i')

    def process_tfbSpriteInfo(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x00, 0xD0)
        _contextDataInfo = self.process_igObject(bs, self.readPointer(bs))

    def process_tfbPhysicsBody(self, bs, offset):
        shouldAddModel = self.addModel(offset)
        if shouldAddModel:
            self.bitAwareSeek(bs, offset, 0x00, 0x24)
            _combinerPrototype = self.process_igObject(bs, self.readPointer(bs))
            self.bitAwareSeek(bs, offset, 0x00, 0x20)
            _node = self.process_igObject(bs, self.readPointer(bs))

    def process_tfbRuntimeTechniqueInstance(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x00, 0x28)
        _geomAttr = self.process_igObject(bs, self.readPointer(bs))

    def process_igEdgeGeometryAttr(self, bs, offset):
        self.models[-1].meshes.append(MeshObject(self.materialCount))
        ssfIgzFile.process_igEdgeGeometryAttr(self, bs, offset)

    def process_tfbActorInfo(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x00, 0xDC)
        _model = self.process_igObject(bs, self.readPointer(bs))

    def process_tfbPhysicsWorld(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x00, 0x20)
        _sceneInfo = self.process_igObject(bs, self.readPointer(bs))

    def process_igVertexBuffer(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x10, 0x08)
        self.models[-1].meshes[-1].vertexCount = bs.readUInt()
        # readMemoryRef = vertexCount again?
        self.bitAwareSeek(bs, offset, 0x28, 0x14)
        _size, _offset, _data = self.readMemoryRefHandle(bs)
        _stride = self.process_igObject(bs, self.readPointer(bs)) # igVertexFormat
        self.bitAwareSeek(bs, offset, 0x38, 0x1C)
        self.models[-1].meshes[-1].packData = bs.readUInt()

        self.models[-1].meshes[-1].vertexBuffers.append(_data)
        self.models[-1].meshes[-1].vertexStrides.append(_stride)

        #print("vertexCount:    ", hex(self.models[-1].meshes[-1].vertexCount))
        #print("vertex offset:  ", hex(_offset))
        #print("vertex buf size:", hex(_size))

    def process_igVertexFormat(self, bs, offset) -> int:
        # abusing this unused property; but might always be 3 (i.e. 0x08/0x10)
        #_extraMem = (self.models[-1].meshes[-1].packData - 2) * (0x10 if self.is64Bit else 0x08)
        self.bitAwareSeek(bs, offset, 0x10, 0x08)
        _vertexSize = bs.readUInt()
        self.bitAwareSeek(bs, offset, 0x18, 0x0C)
        _esize, _, _ebuffer = self.readMemoryRef(bs)
        self.bitAwareSeek(bs, offset, 0x28, 0x14)
        self.models[-1].meshes[-1].platformData = self.readMemoryRef(bs)
        # Platform seems to be unimportant, and there's 4 unknown bytes instead of the stream reference
        #self.bitAwareSeek(bs, offset, 0x38 + _extraMem, 0x1C + _extraMem)
        #self.models[-1].meshes[-1].platform = bs.readUInt()
        self.models[-1].meshes[-1].vertexStreamS.append(_vertexSize)
        self.models[-1].meshes[-1].vertexElements = tuple(igVertexElement(_ebuffer[i:i + 0x0C]) for i in range(0, _esize, 0x0C))

        return _vertexSize

    def process_igIndexBuffer(self, bs, offset):
        # very similar to igVertexBuffer, except that 64bit doesn't have extra igObject ref.
        self.bitAwareSeek(bs, offset, 0x10, 0x08)
        self.models[-1].meshes[-1].indexCount = bs.readUInt()
        # readMemoryRef = indexCount again?
        self.bitAwareSeek(bs, offset, 0x28, 0x14)
        _size, _offset, _data = self.readMemoryRefHandle(bs)
        self.bitAwareSeek(bs, offset, 0x30, 0x1C)
        self.models[-1].meshes[-1].primType = (
            noesis.RPGEO_POINTS,
            noesis.RPGEO_TRIANGLE_STRIP, # unconfirmed
            noesis.RPGEO_TRIANGLE
            #noesis.RPGEO_TRIANGLE ?
            #'IGZ_TRIANGLE_STRIP'
            #noesis.RPGEO_TRIANGLE_FAN
            #noesis.RPGEO_TRIANGLE_QUADS
        )[bs.readInt()]
        self.models[-1].meshes[-1].indexBuffer = _data

        #print("indexCount:    ", hex(self.models[-1].meshes[-1].indexCount))
        #print("index offset:  ", hex(_offset))
        #print("index buf size:", hex(_size))

    def process_igStringRefList(self, bs, offset):
        _count, _, (_, _, refList) = self.process_igDataList(bs, offset)
        if _count:
            self.stringReferences.append(unpack_from(
                IGZ_ENDIAN_SIGN + str(_count) + ('Q' if self.is64Bit else 'I'),
                refList))

    def process_igMaterialAttr(self, bs=None, offset=None):
        self.materialCount += 1

    def process_igMuaMaterialAttr(self, bs, offset):
        #mua mat: 0x0C, 0 padding, 4 floats (mat color?)
        self.process_igMaterialAttr()

    def process_igSceneTexturesInfo(self, bs, offset):
        # process_igNamedObject
        self.bitAwareSeek(bs, offset, 0x20, 0x10) # 32 unconfirmed
        for p in tuple(self.readPointer(bs) for _ in range(bs.readUInt64() if self.is64Bit else bs.readUInt())):
            _ = self.process_igObject(bs, p)

    def process_igTextureBindAttr2(self, bs, offset):
        self.bitAwareSeek(bs, offset, 0x10, 0x08)
        textureType = bs.readUShort()
        #self.bitAwareSeek(bs, offset, 0x18, 0x0C)
        #self.process_igTextureAttr2(bs, self.readPointer(bs))
        # Theoretically, the meshes would be lower in the hierarchy, but this script parses geometry attributes before texture attributes
        self.textures.append((textureType, self.materialCount - 1))

    #def process_igTextureAttr2(self, bs, offset):
    #    self.bitAwareSeek(bs, offset, 0x10, 0x08)
    #    # 2* unk + 3*0 + 5 - 10 int properties (wrap, tile, etc) + 2x dimensions?
    #    bs.read(IGZ_ENDIAN_SIGN + '2H13I4H')

    def process_igImage2(self, bs, offset):
        #texture path?
        self.bitAwareSeek(bs, offset, 0x18, 0x0C)
        imgWidth, imgHeight, _, _ = bs.read(IGZ_ENDIAN_SIGN + '4H')
        # unknown (total 0x30): readMemoryRefHandle?, other small numbers, flags?
        if self.textureFormat:
            self.textures.append(NoeTexture(rapi.getLocalFileName(self.stringList[0]),
                                 imgWidth, imgHeight,
                                 rapi.imageDecodeDXT(self.thumbnails[0][2],
                                                     imgWidth, imgHeight,
                                                     noesis.FOURCC_ATI2)
                                 if self.textureFormat == noesis.NOESISTEX_RGBA32 else
                                 self.thumbnails[0][2], self.textureFormat))

oldArkRegisteredTypes = commonArkRegisteredTypes.copy()
oldArkRegisteredTypes.update({
    "igGroup"                    : igzFile.process_igGroup,
    "igActor2"                   : igzFile.process_igGroup,
    "igIntList"                  : igzFile.process_igIntList,
    "igNodeList"                 : ssfIgzFile.process_igObjectList,
    "igGeometryAttr"             : ssfIgzFile.process_igGeometryAttr,
    "igWiiGeometryAttr"          : ssfIgzFile.process_igGeometryAttr,
    "igBlendMatrixSelect"        : ssfIgzFile.process_igBlendMatrixSelect,
    "igFxMaterialNode"           : igzFile.process_igGroup, # different
    "DrawableList"               : sttIgzFile.process_igObjectList,
    "Drawable"                   : sttIgzFile.process_Drawable,
    "tfbPhysicsModel"            : sttIgzFile.process_tfbPhysicsModel,
    "tfbPhysicsCombinerLink"     : sttIgzFile.process_tfbPhysicsCombinerLink,
    "tfbWorldEntityInfo"         : sttIgzFile.process_tfbEntityInfo,
    "igSceneInfo"                : ssfIgzFile.process_igSceneInfo,
    "igEdgeGeometryAttr"         : sgIgzFile.process_igEdgeGeometryAttr, # different
    "tfbBodyEntityInfo"          : sttIgzFile.process_tfbEntityInfo, # different
    "tfbPhysicsBody"             : sgIgzFile.process_tfbPhysicsBody, # different
    "tfbPhysicsWorld"            : sgIgzFile.process_tfbPhysicsWorld, # different
    "tfbSpriteInfo"              : sgIgzFile.process_tfbSpriteInfo, # different
    "tfbActorInfo"               : sgIgzFile.process_tfbActorInfo, # different
    "tfbRuntimeTechniqueInstance": sgIgzFile.process_tfbRuntimeTechniqueInstance,
    "igSpatialNode"              : igzFile.process_igGroup
})
sgarkRegisteredTypes = oldArkRegisteredTypes
sgarkRegisteredTypes["igVertexBuffer"] = sgIgzFile.process_igVertexBuffer
sgarkRegisteredTypes["igVertexFormat"] = sgIgzFile.process_igVertexFormat
sgarkRegisteredTypes["igIndexBuffer"] = sgIgzFile.process_igIndexBuffer
sgarkRegisteredTypes["igStringRefList"] = sgIgzFile.process_igStringRefList
sgarkRegisteredTypes["igSceneTexturesInfo"] = sgIgzFile.process_igSceneTexturesInfo
sgarkRegisteredTypes["igTextureBindAttr2"] = sgIgzFile.process_igTextureBindAttr2
sgarkRegisteredTypes["igMaterialAttr"] = sgIgzFile.process_igMaterialAttr
sgarkRegisteredTypes["igMuaMaterialAttr"] = sgIgzFile.process_igMuaMaterialAttr
sgarkRegisteredTypes["igImage2"] = sgIgzFile.process_igImage2
sgarkRegisteredTypes["igAttrList"] = ssfIgzFile.process_igObjectList
sgarkRegisteredTypes["igAttrSet"] = ssfIgzFile.process_igAttrSet
sgarkRegisteredTypes["igGeometry"] = ssfIgzFile.process_igGeometry
sgarkRegisteredTypes["asAnimationDatabase"] = ssfIgzFile.process_asAnimationDatabase
sgarkRegisteredTypes["igTransform"] = ssfIgzFile.process_igTransform
sgarkRegisteredTypes["igIntListList"] = igzFile.process_igObjectList # ?
# igNonRefCountedNodeList (seemingly 0 content in igGroup pair with igNodeList); igColorAttr (mat.setDiffuseColor, setSpecularColor, setAmbientColor, setEnvColor, ...); igMuaMaterialAttr; igTextureStateAttr; igTextureAttr2; igGlobalColorStateAttr; igBlendFunctionAttr; igBlendStateAttr; igAlphaFunctionAttr; igAlphaStateAttr; igHandleList = igDataList
# igTransformSequence1_5, igVec3fList, igQuaternionfList, igLongList, igTextureMatrixStateAttr, igVertexBlendStateAttr
# state attributes are a simple boolean (0 or 1) at rel offset 0x18/0x0C

class ssaIgzFile(igzFile): # 0x05
    def __init__(self, version):
        super().__init__(version)
        self.arkRegisteredTypes = oldArkRegisteredTypes

#ssaarkRegisteredTypes = oldArkRegisteredTypes
