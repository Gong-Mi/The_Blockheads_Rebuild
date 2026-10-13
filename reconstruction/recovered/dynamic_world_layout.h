// Recovered model: the DynamicWorld instance layout (66 ivars, offsets 4..9524).
//
// Rows are (offset, name, ivar cell) read out of the binary's own OBJC_IVAR_$_DynamicWorld.* cells, the same
// mechanism the getters use at run time; the Python contract test re-reads the symbol table and requires an
// exact match.
//
// The layout carries one structural fact that a reader should not have to notice by eye: the world's object
// collections are INLINE C++ containers, not Objective-C objects.
//
//     dynamicObjects @60, dynamicObjectsToAdd @840, dynamicObjectsByWorldPosIndex @1620,
//     freeBlocksByPosition @2400
//
// The strides are exactly 780 bytes, which is why a live ObjC-graph walk that follows ivars and checks isas
// stops in front of them: the dynamic objects (Workbench among them) are inside these containers. The strides
// are asserted below, so a build that lost that property would say so.
//
// Field meanings are not claimed beyond the names the binary itself carries.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace blockheads::recovered::dynamic_world_layout {

struct Field {
    std::size_t offset;
    std::string_view name;
    std::uint32_t cell;
};

inline constexpr std::array<Field, 66> kDynamicWorldFields = {{
    {4, "world", 0x00f34190U},
    {8, "worldTileLoader", 0x00f34194U},
    {12, "clientTileLoader", 0x00f34198U},
    {16, "server", 0x00f3419cU},
    {20, "client", 0x00f341a0U},
    {24, "serverClients", 0x00f341a4U},
    {28, "appDatabase", 0x00f341a8U},
    {32, "worldDatabase", 0x00f341acU},
    {36, "dynamicObjectDatabase", 0x00f341b0U},
    {40, "worldSaveDirectory", 0x00f341d4U},
    {44, "blockheads", 0x00f341c0U},
    {48, "netBlockheads", 0x00f341c4U},
    {52, "netBlockheadsWithDisconnectedClients", 0x00f341c8U},
    {56, "clientBlockheadInventoriesToSave", 0x00f341ccU},
    {60, "dynamicObjects", 0x00f341e4U},
    {840, "dynamicObjectsToAdd", 0x00f341e8U},
    {1620, "dynamicObjectsByWorldPosIndex", 0x00f341ecU},
    {2400, "freeBlocksByPosition", 0x00f34238U},
    {2412, "currentlyAddingGlowBlocks", 0x00f34270U},
    {2432, "currentlyAddingObjectIDs", 0x00f34234U},
    {3732, "currentlyLoadingMacroBlocks", 0x00f34244U},
    {5032, "partialUpdateOrderedObjects", 0x00f3423cU},
    {5812, "partialUpdateCurrentIndex", 0x00f34254U},
    {6072, "worldChangedPositions", 0x00f3425cU},
    {6084, "worldChangedSendUnreliablyMacroPositions", 0x00f34224U},
    {6096, "snowChangedMacroPositions", 0x00f34230U},
    {6108, "worldChangedDontSendMacroPositions", 0x00f3422cU},
    {6120, "lightChangedSendUnreliablyMacroPositionsSingleClient", 0x00f3421cU},
    {6504, "waterChangedPositions", 0x00f34268U},
    {6516, "worldContentsChangedPositions", 0x00f34264U},
    {6528, "worldPartialContentChangedPositions", 0x00f34280U},
    {6540, "dynamicWorldChangedMacroPositions", 0x00f34228U},
    {7320, "worldChangedMacroPositions", 0x00f34220U},
    {7332, "portalPositions", 0x00f341d0U},
    {7336, "cache", 0x00f341b4U},
    {7340, "treeDensityNoiseFunction", 0x00f341b8U},
    {7344, "seasonOffsetNoiseFunction", 0x00f341bcU},
    {7352, "dynamicObjectIDCount", 0x00f34208U},
    {7360, "activeBlockheadIndex", 0x00f3420cU},
    {7364, "freeBlockSoundDelay", 0x00f34248U},
    {7368, "hasLoadedBlockheads", 0x00f34218U},
    {7369, "hasRecievedInitialDynamicObjectsDataFromServer", 0x00f34284U},
    {7370, "workbenchHasBeenCrafted", 0x00f34210U},
    {7372, "netCreateDynamicObjects", 0x00f341f4U},
    {7632, "netUpdateDynamicObjects", 0x00f341f8U},
    {7892, "netUpdateCreationDataDynamicObjects", 0x00f341fcU},
    {8152, "netRemoveDynamicObjects", 0x00f34200U},
    {8412, "clientFreeblockArrayToSend", 0x00f341d8U},
    {8416, "randomNumbers", 0x00f341dcU},
    {9440, "randomIndex", 0x00f34258U},
    {9444, "animalSaveCounter", 0x00f34288U},
    {9448, "saveUnreliableCounter", 0x00f3428cU},
    {9452, "sendLightCounter", 0x00f34290U},
    {9456, "saveToDiskCounter", 0x00f34294U},
    {9460, "worldChangedSimulateCounter", 0x00f34260U},
    {9464, "versionOneToTwoConversionList", 0x00f341f0U},
    {9468, "disconnectedClientsSaveDirNames", 0x00f34250U},
    {9472, "disconnectedClientsCachedSaveDictsNotDone", 0x00f34240U},
    {9476, "sendUnreliableCounter", 0x00f3424cU},
    {9480, "clientTreeLifeFraction", 0x00f34274U},
    {9496, "wirePathCreator", 0x00f341e0U},
    {9500, "liveServerClientBlockheadInventories", 0x00f34204U},
    {9504, "avoidFreeblockDupeObjectIds", 0x00f3426cU},
    {9516, "poleItemTakenTimes", 0x00f34214U},
    {9520, "poleItemRestoreRecheckTimer", 0x00f34278U},
    {9524, "poleItemRestoreAddTimer", 0x00f3427cU},
}};

constexpr bool offsetsRise() {
    for (std::size_t i = 1; i < kDynamicWorldFields.size(); ++i)
        if (kDynamicWorldFields[i - 1].offset >= kDynamicWorldFields[i].offset) return false;
    return true;
}
static_assert(offsetsRise(), "the ivar table must be ordered and duplicate-free");

constexpr std::size_t offsetOf(std::string_view want) {
    for (const Field& f : kDynamicWorldFields)
        if (f.name == want) return f.offset;
    return static_cast<std::size_t>(-1);
}

// the inline-container strides: three containers of the same shape, 780 bytes apart
static_assert(offsetOf("dynamicObjectsToAdd") - offsetOf("dynamicObjects") == 780);
static_assert(offsetOf("dynamicObjectsByWorldPosIndex") - offsetOf("dynamicObjectsToAdd") == 780);

}  // namespace blockheads::recovered::dynamic_world_layout
