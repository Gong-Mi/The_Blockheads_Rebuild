#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld world-save cluster (E22).

The DynamicWorld world-persistence cluster: the world-dict builder with its
five-container dirty sweep, the blockhead save collector, the per-macro-tile
dynamic-object saver with its per-client loaded-set bookkeeping, the object
unloader with its registry erases, the world-position change marker and the
client-connect handler:
1 body, 7058 instruction words, from the pinned original libApplication.so
(1.7.6, armeabi-v7a).  Every instruction word is re-verified; tool refuses to
emit on drift.

Verification rules (each one is a claim this file makes about its own evidence):
  * coverage    - the checked-in listing must cover [start, end) exactly once per word,
                  and every word is re-read from the pinned ELF.
  * PIC base    - recomputed from the `add rX, pc, rY` anchor and its pool literal;
                  must equal 0x0105faf4.
  * cells       - selector cells: the slot is base + signed(pool value) and the C string
                  it points at must be the named selector.  Import cells: the slot must be
                  a PLT/GOT slot whose relocation names the import, or - for functions
                  reached through an ABS32 relocation - a relocation whose symbol names
                  it (the route used is recorded per cell).  Ivar cells: the slot
                  holds a pointer to OBJC_IVAR_$_<Class>.<name> in .dynsym plus the
                  offset word.  Class cells: the slot either holds the OBJC_CLASS_$_
                  symbol value (.dynsym) or - for classes imported from the system
                  frameworks - carries an ABS32 relocation whose symbol is the class;
                  both routes are checked, the relocation route is named when used.
  * calls       - the set of bl/blx rows inside the body must equal the spec's set, and
                  every `bl <name>` route's computed target must match ROUTE_TARGETS.
  * branches    - the set of conditional/unconditional b* rows whose destination lands
                  inside the body must equal the spec's set.  Rows outside the body are
                  literal-pool words that mask as branches; they are recorded in
                  `disjoint_branch_rows` instead of being silently dropped.
  * anchors     - the listed instruction texts must match the listing byte for byte.

Machine-generated spec tables + hand-written semantics; see
reconstruction/reverse-v3/native/WORLD_SAVE.md for the prose and boundaries.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
EXPECTED_SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
EXPECTED_BASE = 0x0105FAF4

ROUTE_TARGETS = {
    'bl 0x8b84c8': 0x008b84c8,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.std::__1::__wrap_iter_DynamicObject__std::__1::remove_std::__1.__wrap_iter_DynamicObject___DynamicObject__std::__1::__wrap_iter_DynamicObject___std::__1::__wrap_iter_DynamicObject___DynamicObject_const_': 0x008b6cd4,
    'bl method.std::__1::map_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________.at_unsigned_int_const_': 0x008ba928,
    'bl method.std::__1::pair_std::__1::__tree_iterator_unsigned_int__std::__1::__tree_node_unsigned_int__void___int___bool__std::__1::__tree_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int___.__insert_unique_unsigned_int__unsigned_int_': 0x00912b98,
    'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___._unordered_set__': 0x0057598c,
    'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.unordered_set_std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock____const_': 0x008f7f90,
    'bl method.std::__1::vector_DynamicObject__std::__1::allocator_DynamicObject___.erase_std::__1::__wrap_iter_DynamicObject_const___std::__1::__wrap_iter_DynamicObject_const__': 0x008b6ac0,
    'bl method.unsigned_long_std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.__erase_unique_unsigned_long_long__unsigned_long_long_const_': 0x00913f9c,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__erase_unique_unsigned_long_long__unsigned_long_long_const_': 0x0091496c,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__erase_unique_unsigned_long_long__unsigned_long_long_const_': 0x00913998,
    'bl method.unsigned_long_std::__1::__tree_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int___.__count_unique_unsigned_int__unsigned_int_const__const': 0x00913604,
    'bl method.unsigned_long_std::__1::__tree_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int___.__erase_unique_unsigned_int__unsigned_int_const_': 0x00912644,
    'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_': 0x0052d84c,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp._Unwind_Resume': 0x001c29c0,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__aeabi_memmove': 0x001c3f08,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.macroIndexAtMacroPosition_int__int__World_': 0x00a174a4,
    'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_': 0x00a16ccc,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.objectTypeCanBeLoadedOnlyWhenClientOwnerOnline_int_': 0x008ba904,
    'bl sym.objectTypeHasStaticPosition_int_': 0x008b68ac,
    'bl sym.objectTypeRequiresPartialUpdate_int_': 0x008b6a8c,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='wtl_savegamewithworlddata_',
        method='DynamicWorld -[saveGameWithWorldData:signOwnershipData:]',
        types='v16@0:4@8@12',
        start=9120188,
        end=9128440,
        disasm='disasm_worldtileloader_savegamewithworlddata_signownershipdata_.txt',
        base_add=9120208,
        base_literal=9120904,
        boundary='ARM.exidx end 0x008b49f8 (listing bound); next ObjC IMP 0x008b49f8 DynamicWorld -[saveAndSendOnlyBlocksThatNeedToBeSent]',
        selectors={
                 0x8b2c98: (15215944, 'setObject:forKey:'),
                 0x8b2c9c: (15216056, 'numberWithBool:'),
                 0x8b2cac: (15216052, 'numberWithInt:'),
                 0x8b2cb8: (15216048, 'numberWithUnsignedLong:'),
                 0x8b2cc4: (15215940, 'dictionary'),
                 0x8b2cd4: (15215852, 'release'),
                 0x8b2cdc: (15216084, 'finishEncoding'),
                 0x8b2ce4: (15216080, 'encodeObject:forKey:'),
                 0x8b2cec: (15216076, 'initForWritingWithMutableData:'),
                 0x8b3e08: (15215804, 'alloc'),
                 0x8b3e10: (15216072, 'data'),
                 0x8b3e18: (15216068, 'saveIfNeeded'),
                 0x8b3e1c: (15216060, 'instance'),
                 0x8b3e24: (15216064, 'commitSaveIfNeeded'),
                 0x8b3ef4: (15216088, 'dataWithPropertyList:format:options:error:'),
                 0x8b3efc: (15216092, 'setData:forKey:'),
                 0x8b3f04: (15215816, 'stringWithFormat:'),
                 0x8b3f08: (15215812, 'saveID'),
                 0x8b4298: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8b42a0: (15215884, 'objectForKey:'),
                 0x8b42a8: (15216096, 'removeAllObjects'),
                 0x8b4628: (15216104, 'inventoryNeedsSaving'),
                 0x8b462c: (15216100, 'prepareInventoryForSaving'),
                 0x8b4630: (15216112, 'setInventoryNeedsSaving:'),
                 0x8b4634: (15216108, 'saveBlockheadInventory:'),
                 0x8b49c4: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8b49cc: (15216116, 'saveBlockheads'),
                 0x8b49d4: (15216120, 'saveDynamicObjects'),
                 0x8b49d8: (15216036, 'macroTiles'),
                 0x8b49e0: (15216124, 'savePhysicalBlockForMacroTile:sendReliably:dontSend:onlySaveIfClientsNeedIt:'),
        },
        imports={
                 0x8b2c90: (16332888, '__CFConstantStringClassReference'),
                 0x8b2c94: (17151904, 'objc_msgSend'),
                 0x8b2ca8: (16332872, '__CFConstantStringClassReference'),
                 0x8b2cb4: (16332856, '__CFConstantStringClassReference'),
                 0x8b2ccc: (16332920, '__CFConstantStringClassReference'),
                 0x8b2cd8: (16332984, '__CFConstantStringClassReference'),
                 0x8b2ce0: (16333000, '__CFConstantStringClassReference'),
                 0x8b3ef0: (16332904, '__CFConstantStringClassReference'),
                 0x8b3f00: (16333144, '__CFConstantStringClassReference'),
                 0x8b3f18: (16333128, '__CFConstantStringClassReference'),
                 0x8b3f20: (16332824, '__CFConstantStringClassReference'),
                 0x8b4294: (16333160, '__CFConstantStringClassReference'),
                 0x8b49bc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8b2c8c: (17162280, 'OBJC_IVAR_$_DynamicWorld.versionOneToTwoConversionList', 9464),
                 0x8b2ca0: (17162316, 'OBJC_IVAR_$_DynamicWorld.workbenchHasBeenCrafted', 7370),
                 0x8b2cb0: (17162320, 'OBJC_IVAR_$_DynamicWorld.activeBlockheadIndex', 7360),
                 0x8b2cc8: (17162324, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectIDCount', 7352),
                 0x8b2cd0: (17162328, 'OBJC_IVAR_$_DynamicWorld.poleItemTakenTimes', 9516),
                 0x8b2ce8: (17162204, 'OBJC_IVAR_$_DynamicWorld.portalPositions', 7332),
                 0x8b3f0c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8b3f14: (17162244, 'OBJC_IVAR_$_DynamicWorld.appDatabase', 28),
                 0x8b3f1c: (17162240, 'OBJC_IVAR_$_DynamicWorld.worldDatabase', 32),
                 0x8b429c: (17162208, 'OBJC_IVAR_$_DynamicWorld.clientBlockheadInventoriesToSave', 56),
                 0x8b42a4: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8b4638: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
                 0x8b49c0: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8b49c8: (17162348, 'OBJC_IVAR_$_DynamicWorld.dynamicWorldChangedMacroPositions', 6540),
                 0x8b49d0: (17162340, 'OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions', 7320),
                 0x8b49dc: (17162344, 'OBJC_IVAR_$_DynamicWorld.worldChangedSendUnreliablyMacroPositions', 6084),
                 0x8b49e8: (17162352, 'OBJC_IVAR_$_DynamicWorld.worldChangedDontSendMacroPositions', 6108),
                 0x8b49f0: (17162356, 'OBJC_IVAR_$_DynamicWorld.snowChangedMacroPositions', 6096),
        },
        classes={
                 0x8b2ca4: (15247832, 'OBJC_CLASS_$_NSNumber'),
                 0x8b2cbc: (15247784, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x8b3e0c: (15247848, 'OBJC_CLASS_$_NSKeyedArchiver'),
                 0x8b3e14: (15247844, 'OBJC_CLASS_$_NSMutableData'),
                 0x8b3e20: (15247840, 'OBJC_CLASS_$_TradeMissionManager'),
                 0x8b3e28: (15247836, 'OBJC_CLASS_$_CrystalManager'),
                 0x8b3ef8: (15247824, 'OBJC_CLASS_$_NSPropertyListSerialization'),
                 0x8b3f10: (15247792, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(9120188, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9120436, 'bl loc.imp.objc_msgSend'), (9121496, 'blx r3'), (9124544, 'bl sym.imp.__aeabi_idiv'), (9125172, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (9125984, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (9126916, 'movw r1, 1'), (9128364, 'ldr r0, [fp, -0x3b8]'), (9128436, 'ldrsbteq fp, [sl], -0x2c')],
        calls=[(9120436, 'bl loc.imp.objc_msgSend'), (9120500, 'blx ip'), (9120536, 'blx ip'), (9120596, 'blx r3'), (9120632, 'blx ip'), (9120692, 'blx r3'), (9120728, 'blx ip'), (9120860, 'blx lr'), (9120896, 'blx ip'), (9121104, 'blx lr'), (9121140, 'blx ip'), (9121496, 'blx r3'), (9121512, 'blx r2'), (9121544, 'blx r3'), (9121560, 'blx r2'), (9121592, 'blx r3'), (9121628, 'blx r3'), (9121648, 'blx r3'), (9121708, 'blx ip'), (9121728, 'blx r2'), (9121768, 'blx ip'), (9121788, 'blx r2'), (9121908, 'blx ip'), (9121996, 'blx lr'), (9122256, 'blx ip'), (9122312, 'blx ip'), (9122404, 'blx lr'), (9122440, 'blx ip'), (9122476, 'blx ip'), (9122584, 'blx ip'), (9122684, 'bl sym.imp.memset'), (9122748, 'blx lr'), (9122848, 'bl sym.imp.objc_enumerationMutation'), (9122996, 'blx ip'), (9123032, 'blx ip'), (9123136, 'blx ip'), (9123300, 'blx r2'), (9123320, 'bl sym.imp.memset'), (9123384, 'blx lr'), (9123488, 'bl sym.imp.objc_enumerationMutation'), (9123580, 'blx ip'), (9123600, 'blx r2'), (9123692, 'blx lr'), (9123720, 'blx r3'), (9123832, 'blx ip'), (9123952, 'bl sym.imp.memset'), (9124016, 'blx lr'), (9124116, 'bl sym.imp.objc_enumerationMutation'), (9124208, 'blx ip'), (9124228, 'blx r2'), (9124320, 'blx lr'), (9124348, 'blx r3'), (9124452, 'blx ip'), (9124544, 'bl sym.imp.__aeabi_idiv'), (9124596, 'blx r2'), (9124664, 'blx ip'), (9124708, 'bl sym.imp.__aeabi_idiv'), (9124804, 'blx ip'), (9125172, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (9125312, 'blx r4'), (9125736, 'bl sym.imp.__aeabi_idiv'), (9125832, 'blx lr'), (9125984, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (9126112, 'blx lr'), (9126368, 'bl sym.imp.__aeabi_memmove'), (9126640, 'bl sym.imp.__aeabi_idiv'), (9126736, 'blx lr'), (9126888, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (9127028, 'blx r4'), (9127284, 'bl sym.imp.__aeabi_memmove'), (9127552, 'bl sym.imp.__aeabi_idiv'), (9127648, 'blx lr'), (9127800, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (9127928, 'blx lr'), (9128184, 'bl sym.imp.__aeabi_memmove')],
        branches=[(9120760, 'bne', 9121008), (9120900, 'b', 9121144), (9121820, 'beq', 9121912), (9122016, 'beq', 9122484), (9122032, 'beq', 9122484), (9122496, 'beq', 9122592), (9122760, 'beq', 9123160), (9122840, 'beq', 9122852), (9123064, 'blo', 9122804), (9123156, 'bne', 9122804), (9123160, 'b', 9123164), (9123396, 'beq', 9123856), (9123480, 'beq', 9123492), (9123612, 'beq', 9123724), (9123724, 'b', 9123728), (9123752, 'blo', 9123444), (9123852, 'bne', 9123444), (9123856, 'b', 9123860), (9124028, 'beq', 9124476), (9124108, 'beq', 9124120), (9124240, 'beq', 9124352), (9124352, 'b', 9124356), (9124380, 'blo', 9124072), (9124472, 'bne', 9124072), (9124476, 'b', 9124480), (9124552, 'bls', 9124600), (9124716, 'bls', 9125676), (9125080, 'beq', 9125420), (9125192, 'beq', 9125320), (9125320, 'b', 9125324), (9125380, 'b', 9124908), (9125520, 'beq', 9125668), (9125612, 'b', 9125504), (9125744, 'bls', 9126580), (9126004, 'beq', 9126120), (9126452, 'beq', 9126572), (9126544, 'b', 9126436), (9126648, 'bls', 9127492), (9126908, 'beq', 9127036), (9127368, 'beq', 9127484), (9127460, 'b', 9127352), (9127560, 'bls', 9128372), (9127820, 'beq', 9127936), (9128268, 'beq', 9128364), (9128360, 'b', 9128252)],
        semantics=('saveGameWithWorldData:signOwnershipData: builds the world-level save dict and flushes every dirty position queue. Prologue 0x008b29bc (frame 0xf8+0x800; PIC base 0x105faf4; self at [fp,-0x3d0]).\nDict build: `[[NSMutableDictionary alloc] init]` (class cell 0x8b2a84 ffe2aeb4, init cell 0x8b2a88) -> [-0x3e0]; the world fields are stored with `setObject:forKey:` using the key strings 0xfff33d64 / 0xfff33d54 / 0xfff33d44 and the self ivars ffffe558 / ffffe55c (cells 0x8b2ca0/0x8b2cb0); the signOwnershipData branch (cmp at 0x8b2bf8) stores the NSNumber flag 8 vs 1 for key 0xfff33d84 (movw lr,8 at 0x8b2c1c vs movw lr,1 at 0x8b2d10).\nKeyed-archive pipeline: the class/selector cell chain at 0x8b2e04-0x8b2e9c (cells fffe231c8/ffe2aef4/ffe232d4/ffe2aef0/ffe232d0/ffe232c8/ffe2aeec/ffe232cc/ffe2aee8) resolves the archive read/write pair and the blob sends at 0x8b2ed8-0x8b2f74 (initForWritingWithMutableData: / encodeObject:forKey: / finishEncoding family).\nTHE CONTAINER SWEEP (the load-bearing core): five 8-byte-stride C++ containers are walked in order - ivar ffffe570 (cell 0x8b49d0, @0x8b3b00), ffffe574 (0x8b49dc, @0x8b3f34), ffffe578 + 0x120 (0x8b49c8, @0x8b3a88/0x8b3aa0), ffffe57c (0x8b49e8, @0x8b42bc), ffffe580 (0x8b49f0, @0x8b464c). Per container: count = (end-start)/8 via __aeabi_idiv (0x8b3ac0); when > 0 an objc notify (cells 0x8b49cc ffe23300 / 0x8b49d4 ffe23304) runs on self; then per entry the (x, y) pair drives the C call `macroTileAtMacroPostion(int, int, MacroTile*, World*)` (0x8b3d34 / 0x8b4060 / 0x8b43e8 / 0x8b4778) through the world ivar ffffe4e4 (0x8b49c0); a non-NULL tile calls `[world savePhysicalBlockForMacroTile:tile sendReliably:? dontSend:? onlySaveIfClientsNeedIt:?]` (sel cell 0x8b49e0 ffe23308) with per-container flags (sendReliably 1 vs 0 read at 0x8b4404 vs 0x8b4078); success erases the entry (libc++ erase: __aeabi_memmove with the /8 stride + the mvn -8 tree fixups at 0x8b4238-0x8b4290 and siblings). Tail: the ffffe580 sweep ends at 0x8b49ac; epilogue 0x8b49b4 (guard cell 0x8b2c94).\n'),
    ),
    dict(
        name='wtl_saveblockheads',
        method='DynamicWorld -[saveBlockheads]',
        types='v8@0:4',
        start=9137932,
        end=9143496,
        disasm='disasm_worldtileloader_saveblockheads.txt',
        base_add=9137952,
        base_literal=9141864,
        boundary='ARM.exidx end 0x008b84c8 (listing bound); next ObjC IMP 0x008b8634 DynamicWorld -[saveBlockheadInventory:]',
        selectors={
                 0x8b7e70: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8b7e78: (15216144, 'array'),
                 0x8b7e80: (15216008, 'addObject:'),
                 0x8b7e84: (15216172, 'getSaveDictIncludingWorkbenchOrInterationObject:'),
                 0x8b7e90: (15215944, 'setObject:forKey:'),
                 0x8b7e94: (15215940, 'dictionary'),
                 0x8b7e9c: (15216184, 'appendData:'),
                 0x8b7ea0: (15216180, 'dataWithBytes:length:'),
                 0x8b7ea8: (15216176, 'gzipDeflate'),
                 0x8b7eac: (15216188, 'length'),
                 0x8b7eb0: (15216192, 'sendDataToServer:reliable:'),
                 0x8b7ebc: (15216196, 'raise:format:'),
                 0x8b8438: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8b843c: (15216144, 'array'),
                 0x8b8444: (15216008, 'addObject:'),
                 0x8b8448: (15216172, 'getSaveDictIncludingWorkbenchOrInterationObject:'),
                 0x8b8450: (15215944, 'setObject:forKey:'),
                 0x8b8454: (15215940, 'dictionary'),
                 0x8b8464: (15216196, 'raise:format:'),
                 0x8b8470: (15216092, 'setData:forKey:'),
                 0x8b847c: (15216176, 'gzipDeflate'),
                 0x8b8480: (15215864, 'count'),
                 0x8b848c: (15216200, 'clientSaveDir'),
                 0x8b8490: (15215884, 'objectForKey:'),
                 0x8b849c: (15215912, 'unsignedLongValue'),
                 0x8b84a0: (15216160, 'uniqueID'),
                 0x8b84a4: (15216204, 'replaceObjectAtIndex:withObject:'),
                 0x8b84b0: (15215816, 'stringWithFormat:'),
                 0x8b84b8: (15216212, 'arrayWithArray:'),
                 0x8b84bc: (15216208, 'allKeys'),
                 0x8b84c0: (15215996, 'removeObject:'),
                 0x8b84c4: (15215860, 'removeObjectForKey:'),
        },
        imports={
                 0x8b7e6c: (17151904, 'objc_msgSend'),
                 0x8b7e8c: (16333064, '__CFConstantStringClassReference'),
                 0x8b7eb4: (16333208, '__CFConstantStringClassReference'),
                 0x8b7eb8: (16333224, '__CFConstantStringClassReference'),
                 0x8b8430: (16333048, '__CFConstantStringClassReference'),
                 0x8b8434: (17151904, 'objc_msgSend'),
                 0x8b844c: (16333064, '__CFConstantStringClassReference'),
                 0x8b845c: (16333208, '__CFConstantStringClassReference'),
                 0x8b8460: (16333224, '__CFConstantStringClassReference'),
                 0x8b846c: (16333016, '__CFConstantStringClassReference'),
                 0x8b8478: (16333240, '__CFConstantStringClassReference'),
                 0x8b8498: (16333080, '__CFConstantStringClassReference'),
                 0x8b84a8: (16333256, '__CFConstantStringClassReference'),
                 0x8b84ac: (16333032, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8b7e74: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8b7e88: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8b8474: (17162240, 'OBJC_IVAR_$_DynamicWorld.worldDatabase', 32),
                 0x8b8484: (17162372, 'OBJC_IVAR_$_DynamicWorld.disconnectedClientsCachedSaveDictsNotDone', 9472),
                 0x8b8488: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
        },
        classes={
                 0x8b7e7c: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
                 0x8b7e98: (15247784, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x8b7ea4: (15247844, 'OBJC_CLASS_$_NSMutableData'),
                 0x8b7ec0: (15247852, 'OBJC_CLASS_$_NSException'),
                 0x8b8440: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
                 0x8b8458: (15247784, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x8b8468: (15247852, 'OBJC_CLASS_$_NSException'),
                 0x8b84b4: (15247792, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(9137932, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9137988, 'ldr r7, [0x008b7e74]'), (9138184, 'blx lr'), (9138720, 'bl 0x8b84c8'), (9138784, 'movw r0, 0'), (9142212, 'ldr r5, [0x008b8488]'), (9142256, 'ldr r0, [0x008b8484]'), (9143120, 'ldr r2, [0x008b84c4]'), (9143492, 'invalid')],
        calls=[(9138096, 'blx r4'), (9138120, 'bl sym.imp.memset'), (9138184, 'blx lr'), (9138284, 'bl sym.imp.objc_enumerationMutation'), (9138428, 'blx ip'), (9138468, 'blx r3'), (9138568, 'blx ip'), (9138668, 'blx r2'), (9138712, 'blx ip'), (9138720, 'bl 0x8b84c8'), (9138916, 'blx r6'), (9138964, 'blx ip'), (9138992, 'blx r3'), (9139056, 'blx r3'), (9139088, 'blx r3'), (9139192, 'blx ip'), (9139288, 'blx r4'), (9139376, 'blx ip'), (9139400, 'bl sym.imp.NSLog'), (9139488, 'blx ip'), (9139588, 'blx r4'), (9139652, 'blx r2'), (9139756, 'bl sym.imp.memset'), (9139820, 'blx lr'), (9139920, 'bl sym.imp.objc_enumerationMutation'), (9140004, 'blx r3'), (9140108, 'blx r3'), (9140212, 'blx lr'), (9140260, 'blx lr'), (9140396, 'blx ip'), (9140440, 'bl sym.imp.memset'), (9140488, 'blx lr'), (9140588, 'bl sym.imp.objc_enumerationMutation'), (9140636, 'bl loc.imp.objc_msgSend'), (9140652, 'bl loc.imp.objc_msgSend'), (9140684, 'bl loc.imp.objc_msgSend'), (9140832, 'blx ip'), (9140928, 'blx ip'), (9140984, 'blx r3'), (9141092, 'blx ip'), (9141212, 'bl sym.imp.memset'), (9141276, 'blx lr'), (9141376, 'bl sym.imp.objc_enumerationMutation'), (9141540, 'blx r6'), (9141576, 'blx r3'), (9141620, 'blx ip'), (9141628, 'bl 0x8b84c8'), (9141668, 'blx r2'), (9141816, 'blx ip'), (9141852, 'blx ip'), (9142044, 'blx r4'), (9142148, 'blx ip'), (9142368, 'blx r2'), (9142400, 'blx r3'), (9142424, 'bl sym.imp.memset'), (9142488, 'blx lr'), (9142588, 'bl sym.imp.objc_enumerationMutation'), (9142672, 'blx r3'), (9142744, 'blx r3'), (9142848, 'blx ip'), (9142956, 'bl sym.imp.memset'), (9143004, 'blx lr'), (9143104, 'bl sym.imp.objc_enumerationMutation'), (9143204, 'blx r3'), (9143304, 'blx ip')],
        branches=[(9138196, 'beq', 9138592), (9138276, 'beq', 9138288), (9138496, 'blo', 9138240), (9138588, 'bne', 9138240), (9138592, 'b', 9138596), (9138740, 'beq', 9139500), (9138780, 'beq', 9139388), (9139008, 'beq', 9139200), (9139100, 'bls', 9139200), (9139196, 'b', 9139292), (9139384, 'b', 9139496), (9139496, 'b', 9139592), (9139660, 'bls', 9143336), (9139832, 'beq', 9141116), (9139912, 'beq', 9139924), (9140024, 'beq', 9140992), (9140128, 'bne', 9140264), (9140500, 'beq', 9140856), (9140580, 'beq', 9140592), (9140704, 'bne', 9140724), (9140708, 'b', 9140712), (9140720, 'b', 9140860), (9140760, 'blo', 9140544), (9140852, 'bne', 9140544), (9140856, 'b', 9140860), (9140868, 'beq', 9140936), (9140932, 'b', 9140988), (9140988, 'b', 9140992), (9140992, 'b', 9140996), (9141020, 'blo', 9139876), (9141112, 'bne', 9139876), (9141116, 'b', 9141120), (9141288, 'beq', 9142172), (9141368, 'beq', 9141380), (9141688, 'beq', 9141956), (9141860, 'b', 9142048), (9142048, 'b', 9142052), (9142076, 'blo', 9141332), (9142168, 'bne', 9141332), (9142172, 'b', 9142176), (9142500, 'beq', 9142872), (9142580, 'beq', 9142592), (9142692, 'beq', 9142748), (9142748, 'b', 9142752), (9142776, 'blo', 9142544), (9142868, 'bne', 9142544), (9142872, 'b', 9142876), (9143016, 'beq', 9143328), (9143096, 'beq', 9143108), (9143232, 'blo', 9143060), (9143324, 'bne', 9143060), (9143328, 'b', 9143332), (9143332, 'b', 9143336)],
        semantics=("saveBlockheads collects every blockhead's save dict, serializes it and stores or sends it, then prunes the work lists. Prologue 0x008b6f0c (frame 0x1b8+0x400; base 0x105faf4).\nCollect: enumerate the blockheads collection ivar ffffe4f8 (cell 0x8b7e74, @0x8b6f44) with countByEnumeratingWithState: (cell 0x8b7e70 ffe231ec); per item a class check (`isKindOfClass:` cell 0x8b7e78 ffe2331c, class cell 0x8b7e7c ffe2aeb0) plus memset of the state; the self.client ivar gate (ffffe518, cell 0x8b7e88, @0x8b7008) decides the per-item call (sel cell 0x8b7e84 ffe23338 with r2 = (self.client != 0)) whose result accumulates into an array [-0x28].\nSerialize: a fresh `[[NSMutableDictionary ...]` pair (cells 0x8b7e94 ffe23250 / 0x8b7e98 ffe2aeb4) -> [-0x98]; the array is stored; then `bl 0x8b84c8` (the shared serializer helper, @0x8b7220) -> [-0x9c]; NULL exits (0x8b752c). When self.client (ffffe518) != 0 the client send path at 0x8b74bc runs; otherwise the keyed-archive write path (0x8b7260-0x8b7f0c): NSKeyedArchiver (class cell 0x8b7ea4 ffe2aef0) with initForWritingWithMutableData: (cell 0x8b7ea0 ffe23340), the encodeObject:forKey: chain (cell 0x8b7ea8 ffe2333c / 0x8b7e9c ffe23344) and finishEncoding.\nDatabase write + prune: the dict is stored into the world database (setObject:forKey: chain 0x8b7c50-0x8b7f40 region, stringWithFormat: cell 0x8b7e98 family); then prune passes: over ivar ffffe4f0 (cell 0x8b8488, @0x8b7fc4) with sel ffe23354 (cell 0x8b848c) + intValue compare + `removeObject:` (cell 0x8b84c0 ffe23288); over ivar ffffe590 (cell 0x8b8484, @0x8b7ff0) with sel ffe23360/ffe2335c (cells 0x8b84b8/0x8b84bc) + removeObject: (0x8b81b4); and a second pass over ffffe590 with sel ffe23200 (cell 0x8b84c4, @0x8b8350). Epilogue 0x8b8428.\n"),
    ),
    dict(
        name='wtl_savedynamicobjectsform',
        method='DynamicWorld -[saveDynamicObjectsForMacroTile:objectType:xPos:yPos:]',
        types='v24@0:4^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8i12i16i20',
        start=9147196,
        end=9152772,
        disasm='disasm_worldtileloader_savedynamicobjectsformacrotile_objecttyp.txt',
        base_add=9147212,
        base_literal=9151120,
        boundary='ARM.exidx end 0x008ba904 (listing bound); next ObjC IMP 0x008baa54 DynamicWorld -[loadDynamicObjectsOfType:fromData:physicalBlock:loadedPortal:clientOwnedID:]',
        selectors={
                 0x8ba2a4: (15216144, 'array'),
                 0x8ba2ac: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8ba2b4: (15215940, 'dictionary'),
                 0x8ba2bc: (15216244, 'worldIndicesContainingTamedAnimals'),
                 0x8ba2c0: (15215884, 'objectForKey:'),
                 0x8ba2c4: (15215944, 'setObject:forKey:'),
                 0x8ba710: (15215864, 'count'),
                 0x8ba85c: (15216144, 'array'),
                 0x8ba864: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8ba86c: (15215940, 'dictionary'),
                 0x8ba874: (15216244, 'worldIndicesContainingTamedAnimals'),
                 0x8ba878: (15215884, 'objectForKey:'),
                 0x8ba87c: (15215944, 'setObject:forKey:'),
                 0x8ba880: (15215864, 'count'),
                 0x8ba884: (15216168, 'objectType'),
                 0x8ba888: (15216260, 'chestType'),
                 0x8ba88c: (15216264, 'inventoryDataAllowingEmpty:'),
                 0x8ba890: (15216092, 'setData:forKey:'),
                 0x8ba89c: (15215816, 'stringWithFormat:'),
                 0x8ba8a0: (15216160, 'uniqueID'),
                 0x8ba8ac: (15216268, 'getSaveDictIncludingInventory:'),
                 0x8ba8b0: (15216248, 'needsChestSave'),
                 0x8ba8b4: (15216256, 'getChestSaveDict'),
                 0x8ba8b8: (15216252, 'setNeedsChestSave:'),
                 0x8ba8c4: (15216196, 'raise:format:'),
                 0x8ba8d4: (15216272, 'getSaveDict'),
                 0x8ba8d8: (15216276, 'clientIDForSavingSeperatelyAndOnlyLoadingWhilePlayerOnline'),
                 0x8ba8e0: (15216280, 'isEqualToString:'),
                 0x8ba8e4: (15216008, 'addObject:'),
        },
        imports={
                 0x8ba294: (16333304, '__CFConstantStringClassReference'),
                 0x8ba2a0: (17151904, 'objc_msgSend'),
                 0x8ba858: (17151904, 'objc_msgSend'),
                 0x8ba894: (16333288, '__CFConstantStringClassReference'),
                 0x8ba8bc: (16333208, '__CFConstantStringClassReference'),
                 0x8ba8c0: (16333336, '__CFConstantStringClassReference'),
                 0x8ba8cc: (16333320, '__CFConstantStringClassReference'),
                 0x8ba8dc: (16333352, '__CFConstantStringClassReference'),
                 0x8ba8ec: (16333064, '__CFConstantStringClassReference'),
                 0x8ba8f0: (16333384, '__CFConstantStringClassReference'),
                 0x8ba8f4: (16333368, '__CFConstantStringClassReference'),
                 0x8ba8f8: (16333416, '__CFConstantStringClassReference'),
                 0x8ba8fc: (16333400, '__CFConstantStringClassReference'),
                 0x8ba900: (16333432, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x8ba298: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8ba29c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8ba2b0: (17162248, 'OBJC_IVAR_$_DynamicWorld.serverClients', 24),
                 0x8ba854: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8ba868: (17162248, 'OBJC_IVAR_$_DynamicWorld.serverClients', 24),
                 0x8ba8a8: (17162236, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectDatabase', 36),
        },
        classes={
                 0x8ba2a8: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
                 0x8ba2b8: (15247784, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x8ba860: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
                 0x8ba870: (15247784, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x8ba8a4: (15247792, 'OBJC_CLASS_$_NSString'),
                 0x8ba8c8: (15247852, 'OBJC_CLASS_$_NSException'),
        },
        instructions=[(9147196, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9147292, 'b 0x8ba84c'), (9147496, 'bl sym.macroIndexAtMacroPosition_int__int__World_'), (9147508, 'bl sym.objectTypeCanBeLoadedOnlyWhenClientOwnerOnline_int_'), (9148000, 'bl method.std::__1::map_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________.at_unsigned_int_const_'), (9148792, 'movw r0, 0x1388'), (9149396, 'ldr r0, [fp, -0x78]'), (9150984, 'bl 0x8b84c8'), (9152124, 'bl method.unsigned_long_std::__1::__tree_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int___.__erase_unique_unsigned_int__unsigned_int_const_'), (9152768, 'invalid')],
        calls=[(9147276, 'bl sym.imp.NSLog'), (9147452, 'blx r3'), (9147496, 'bl sym.macroIndexAtMacroPosition_int__int__World_'), (9147508, 'bl sym.objectTypeCanBeLoadedOnlyWhenClientOwnerOnline_int_'), (9147640, 'blx r2'), (9147664, 'bl sym.imp.memset'), (9147728, 'blx lr'), (9147828, 'bl sym.imp.objc_enumerationMutation'), (9147960, 'blx lr'), (9147984, 'blx r2'), (9148000, 'bl method.std::__1::map_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________.at_unsigned_int_const_'), (9148036, 'bl method.unsigned_long_std::__1::__tree_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int___.__count_unique_unsigned_int__unsigned_int_const__const'), (9148108, 'blx r3'), (9148200, 'blx ip'), (9148256, 'blx lr'), (9148364, 'blx ip'), (9148440, 'blx r2'), (9148540, 'bl sym.imp.memset'), (9148592, 'blx lr'), (9148692, 'bl sym.imp.objc_enumerationMutation'), (9148764, 'blx r2'), (9148928, 'blx r2'), (9149016, 'blx ip'), (9149036, 'blx r2'), (9149048, 'bl 0x8b84c8'), (9149196, 'bl loc.imp.objc_msgSend'), (9149248, 'bl loc.imp.objc_msgSend'), (9149284, 'blx ip'), (9149384, 'blx r4'), (9149448, 'blx r2'), (9149532, 'blx lr'), (9149696, 'bl loc.imp.objc_msgSend'), (9149760, 'bl loc.imp.objc_msgSend'), (9149796, 'blx ip'), (9149864, 'blx ip'), (9149936, 'blx r2'), (9150028, 'blx r4'), (9150072, 'blx ip'), (9150156, 'blx ip'), (9150248, 'blx r3'), (9150340, 'blx ip'), (9150396, 'blx lr'), (9150428, 'bl loc.imp.objc_msgSend'), (9150448, 'bl loc.imp.objc_msgSend'), (9150464, 'bl method.std::__1::map_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________.at_unsigned_int_const_'), (9150524, 'bl method.std::__1::pair_std::__1::__tree_iterator_unsigned_int__std::__1::__tree_node_unsigned_int__void___int___bool__std::__1::__tree_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int___.__insert_unique_unsigned_int__unsigned_int_'), (9150676, 'blx r3'), (9150788, 'blx ip'), (9150932, 'blx r2'), (9150976, 'blx ip'), (9150984, 'bl 0x8b84c8'), (9151020, 'bl sym.imp.NSLog'), (9151112, 'blx r4'), (9151304, 'blx r6'), (9151388, 'blx lr'), (9151424, 'blx ip'), (9151512, 'bl sym.imp.memset'), (9151560, 'blx lr'), (9151660, 'bl sym.imp.objc_enumerationMutation'), (9151836, 'blx r8'), (9151872, 'blx r3'), (9151916, 'blx ip'), (9151936, 'blx r2'), (9152048, 'blx lr'), (9152072, 'blx r2'), (9152088, 'bl method.std::__1::map_unsigned_int__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int_____std::__1::less_unsigned_int___std::__1::allocator_std::__1::pair_unsigned_int_const__std::__1::set_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int________.at_unsigned_int_const_'), (9152124, 'bl method.unsigned_long_std::__1::__tree_unsigned_int__std::__1::less_unsigned_int___std::__1::allocator_unsigned_int___.__erase_unique_unsigned_int__unsigned_int_const_'), (9152136, 'bl 0x8b84c8'), (9152172, 'bl sym.imp.NSLog'), (9152264, 'blx r4'), (9152400, 'blx lr'), (9152448, 'blx lr'), (9152556, 'blx ip')],
        branches=[(9147260, 'bne', 9147280), (9147288, 'bne', 9147296), (9147292, 'b', 9152588), (9147332, 'beq', 9147352), (9147344, 'beq', 9147352), (9147348, 'b', 9152588), (9147364, 'bne', 9147372), (9147368, 'b', 9152588), (9147384, 'bne', 9147392), (9147388, 'b', 9152588), (9147520, 'beq', 9148396), (9147740, 'beq', 9148388), (9147820, 'beq', 9147832), (9148044, 'beq', 9148264), (9148128, 'bne', 9148260), (9148260, 'b', 9148264), (9148264, 'b', 9148268), (9148292, 'blo', 9147784), (9148384, 'bne', 9147784), (9148388, 'b', 9148392), (9148392, 'b', 9148396), (9148448, 'bls', 9150820), (9148604, 'beq', 9150812), (9148684, 'beq', 9148696), (9148776, 'bne', 9150688), (9148788, 'bne', 9148828), (9148816, 'blt', 9148824), (9148820, 'b', 9150692), (9148824, 'b', 9148828), (9148864, 'bne', 9150684), (9148884, 'bne', 9149396), (9148940, 'beq', 9149392), (9149068, 'beq', 9149296), (9149292, 'b', 9149388), (9149388, 'b', 9149392), (9149392, 'b', 9149880), (9149404, 'bne', 9149876), (9149456, 'beq', 9149872), (9149552, 'beq', 9149804), (9149872, 'b', 9149876), (9149876, 'b', 9149880), (9149892, 'bne', 9149944), (9150092, 'beq', 9150628), (9150168, 'bne', 9150628), (9150184, 'beq', 9150624), (9150268, 'bne', 9150400), (9150624, 'b', 9150680), (9150680, 'b', 9150684), (9150684, 'b', 9150688), (9150688, 'b', 9150692), (9150716, 'blo', 9148648), (9150808, 'bne', 9148648), (9150812, 'b', 9150816), (9150816, 'b', 9150820), (9150856, 'bne', 9152588), (9151004, 'bne', 9151176), (9151116, 'b', 9151432), (9151572, 'beq', 9152580), (9151652, 'beq', 9151664), (9151944, 'bne', 9152132), (9152156, 'bne', 9152276), (9152268, 'b', 9152456), (9152456, 'b', 9152460), (9152484, 'blo', 9151616), (9152576, 'bne', 9151616), (9152580, 'b', 9152584), (9152584, 'b', 9152588)],
        semantics=("saveDynamicObjectsForMacroTile:objectType:xPos:yPos: persists one macro tile's dynamic objects of one type, per client. Prologue 0x008b933c (frame 0x4a0; base 0x105faf4). Arguments: macroTile [-0x74], objectType [-0x78], xPos [-0x7c], yPos [-0x80], self [-0x6c].\nGates: objectType == 0xf -> NSLog (string cell 0x8ba294 fff33f04); objectType == 0x15 -> return (0x8b939c -> 0x8ba84c); when self.client (ffffe518, cell 0x8ba298) != 0 and objectType != 0x2e -> return (0x8b93c0-0x8b93d4); macroTile == 0 -> return; the byte at [macroTile+2] == 0 -> return (0x8b93f0).\nIndexing: `macroIndexAtMacroPosition(int, int, World*)` (C call 0x8b9468) -> [-0x8c].\nCapability branch: `objectTypeCanBeLoadedOnlyWhenClientOwnerOnline(int)` (C call 0x8b9474); when true the serverClients collection (ffffe514, cell 0x8ba2b0) is enumerated: per client the sel ffe23380 (cell 0x8ba2bc) + `objectForKey:` (cell 0x8ba2c0 ffe23218) lookup feeds `std::__1::map<unsigned int, std::__1::set<unsigned int>*>::at(objectType)` (C++ call 0x8b9660), then `__count_unique` (0x8b9684) / `__tree insert` / `__erase_unique(macroIndex)` (0x8ba67c) maintain the per-client loaded-macro sets; mismatch paths re-check via isKindOfClass: (class cell 0x8ba2a8 ffe2aeb0) and call removeObjectFrom... (cells 0x8ba2c4 ffe23254 + 0x8ba2a4 ffe2331c region).\nMain walk: the tile's object collection at [macroTile+0xc] (count via cell 0x8ba710 ffe23204, @0x8b97ec) is enumerated; per object `[obj objectType]` (cell 0x8ba884 ffe23334) must equal the argument; the **FreeBlock (0xe) save cap is 5000** (`movw r0, 0x1388`, counter [-0x104], @0x8b9978); the type 0x2b branch at 0x8b9bd4; the type 0x2e branch at 0x8b9bd8 (sel ffe23390 gate == 4 (cell 0x8ba888), calls ffe23394 (cell 0x8ba88c) with sxtb and ffe23398 (cell 0x8ba8ac), stringWithFormat: key 0xfff33ef4).\nSerialize + store: `bl 0x8b84c8` (shared serializer; @0x8ba208 and @0x8ba688); a NULL result logs NSLog 0xfff33f44 (cell 0x8ba8f4) plus the formatted 0xfff33ea4 (cell 0x8ba8bc) / 0xfff33f54 path (cells 0x8ba8c4 ffe23350 + class 0x8ba8c8 ffe2aef8); a non-NULL result is keyed with stringWithFormat: (0xfff33f84 / 0xfff33f74) and stored with `setObject:forKey:` (sel cell 0x8ba890 ffe232e8) into the dynamic-object database ivar ffffe508 (cell 0x8ba8a8). The final client-owner pass (0x8ba164+, gated by self.client != 0 return at 0x8ba188) repeats the serialize+store for the client cases. Epilogue 0x8ba84c.\n"),
    ),
    dict(
        name='wtl_removedynamicobjectsfo',
        method='DynamicWorld -[removeDynamicObjectsForMacroTile:]',
        types='v12@0:4^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8',
        start=9133652,
        end=9136300,
        disasm='disasm_worldtileloader_removedynamicobjectsformacrotile_.txt',
        base_add=9133668,
        base_literal=9136296,
        boundary='ARM.exidx end 0x008b68ac (listing bound); next ObjC IMP 0x008b6f0c DynamicWorld -[saveBlockheads]',
        selectors={
                 0x8b6850: (15215864, 'count'),
                 0x8b6854: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8b6858: (15216168, 'objectType'),
                 0x8b6864: (15216160, 'uniqueID'),
                 0x8b6870: (15216012, 'pos'),
                 0x8b6890: (15215968, 'autorelease'),
                 0x8b6898: (15215996, 'removeObject:'),
                 0x8b68a0: (15215844, 'blockheadWillBeUnloaded:'),
                 0x8b68a4: (15215852, 'release'),
        },
        imports={
                 0x8b684c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8b6860: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8b6868: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x8b686c: (17162360, 'OBJC_IVAR_$_DynamicWorld.currentlyAddingObjectIDs', 2432),
                 0x8b6874: (17162364, 'OBJC_IVAR_$_DynamicWorld.freeBlocksByPosition', 2400),
                 0x8b6878: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8b6880: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
                 0x8b688c: (17162368, 'OBJC_IVAR_$_DynamicWorld.partialUpdateOrderedObjects', 5032),
                 0x8b6894: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
                 0x8b689c: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
        },
        classes={},
        instructions=[(9133652, 'push {r4, r5, r6, sl, fp, lr}'), (9133692, 'ldr r0, [r0, 4]'), (9134088, 'movw r0, 0'), (9134460, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__erase_unique_unsigned_long_long__unsigned_long_long_const_'), (9134956, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9135048, 'bl sym.objectTypeHasStaticPosition_int_'), (9135404, 'bl sym.objectTypeRequiresPartialUpdate_int_'), (9135704, 'bl method.std::__1::__wrap_iter_DynamicObject__std::__1::remove_std::__1.__wrap_iter_DynamicObject___DynamicObject__std::__1::__wrap_iter_DynamicObject___std::__1::__wrap_iter_DynamicObject___DynamicObject_const_'), (9135916, 'bl method.std::__1::vector_DynamicObject__std::__1::allocator_DynamicObject___.erase_std::__1::__wrap_iter_DynamicObject_const___std::__1::__wrap_iter_DynamicObject_const__'), (9136296, 'rsbseq sb, sl, r8, lsl 25')],
        calls=[(9133760, 'blx r2'), (9133852, 'bl sym.imp.memset'), (9133904, 'blx lr'), (9134004, 'bl sym.imp.objc_enumerationMutation'), (9134076, 'blx r2'), (9134208, 'blx lr'), (9134248, 'blx ip'), (9134296, 'blx r2'), (9134352, 'bl loc.imp.objc_msgSend'), (9134416, 'bl loc.imp.objc_msgSend'), (9134460, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__erase_unique_unsigned_long_long__unsigned_long_long_const_'), (9134492, 'bl loc.imp.objc_msgSend'), (9134552, 'bl loc.imp.objc_msgSend'), (9134596, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__erase_unique_unsigned_long_long__unsigned_long_long_const_'), (9134628, 'bl loc.imp.objc_msgSend'), (9134688, 'bl loc.imp.objc_msgSend'), (9134724, 'bl method.unsigned_long_std::__1::__hash_table_unsigned_long_long__std::__1::hash_unsigned_long_long___std::__1::equal_to_unsigned_long_long___std::__1::allocator_unsigned_long_long___.__erase_unique_unsigned_long_long__unsigned_long_long_const_'), (9134776, 'blx r3'), (9134864, 'bl loc.imp.objc_msgSend_stret'), (9134900, 'bl sym.imp.memset'), (9134956, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9134996, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__erase_unique_unsigned_long_long__unsigned_long_long_const_'), (9135044, 'blx r2'), (9135048, 'bl sym.objectTypeHasStaticPosition_int_'), (9135140, 'blx lr'), (9135220, 'bl loc.imp.objc_msgSend_stret'), (9135256, 'bl sym.imp.memset'), (9135312, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9135352, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__DynamicObject___std::__1::__map_value_compare_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__DynamicObject_____.__erase_unique_unsigned_long_long__unsigned_long_long_const_'), (9135400, 'blx r2'), (9135404, 'bl sym.objectTypeRequiresPartialUpdate_int_'), (9135452, 'bl loc.imp.objc_msgSend'), (9135516, 'bl loc.imp.objc_msgSend'), (9135608, 'bl loc.imp.objc_msgSend'), (9135704, 'bl method.std::__1::__wrap_iter_DynamicObject__std::__1::remove_std::__1.__wrap_iter_DynamicObject___DynamicObject__std::__1::__wrap_iter_DynamicObject___std::__1::__wrap_iter_DynamicObject___DynamicObject_const_'), (9135784, 'bl loc.imp.objc_msgSend'), (9135916, 'bl method.std::__1::vector_DynamicObject__std::__1::allocator_DynamicObject___.erase_std::__1::__wrap_iter_DynamicObject_const___std::__1::__wrap_iter_DynamicObject_const__'), (9135964, 'blx r2'), (9136076, 'blx ip'), (9136168, 'blx r2')],
        branches=[(9133712, 'beq', 9136112), (9133768, 'bls', 9136108), (9133916, 'beq', 9136100), (9133996, 'beq', 9134008), (9134084, 'bne', 9134256), (9134124, 'beq', 9134252), (9134252, 'b', 9135976), (9134304, 'beq', 9135972), (9134784, 'bne', 9135004), (9134848, 'beq', 9134872), (9134868, 'b', 9134904), (9135060, 'beq', 9135360), (9135204, 'beq', 9135228), (9135224, 'b', 9135260), (9135416, 'beq', 9135924), (9135972, 'b', 9135976), (9135976, 'b', 9135980), (9136004, 'blo', 9133960), (9136096, 'bne', 9133960), (9136100, 'b', 9136104), (9136104, 'b', 9136108), (9136108, 'b', 9136112)],
        semantics=("removeDynamicObjectsForMacroTile: unloads and unregisters every dynamic object of a macro tile's list. Prologue 0x008b5e54 (frame 0x298; base 0x105faf4). Argument: macroTile (r2). Gates: [macroTile+4] == 0 -> return (0x8b5e90); the collection at [macroTile+0xc] must have count > 0 (cell 0x8b6850 ffe23204, else 0x8b67ec).\nPer object ([obj objectType] via cell 0x8b6858 ffe23334):\n- == 0x18 (Blockhead): when self.client (ffffe518, cell 0x8b6894) == 0: `[self removeObject:obj]` (cell 0x8b6898 ffe23288) over netBlockheads (ffffe4f4, cell 0x8b689c) and `blockheadWillBeUnloaded:` (cell 0x8b68a0 ffe231f0) @0x8b6008-0x8b60a8.\n- == 0x15: skip (0x8b60e0).\n- otherwise `[obj uniqueID]` (cell 0x8b6864 ffe2332c) yields the u64 ID, and three registries erase it: `std::__1::__tree<...pair<u64,DynamicObject*>>::__erase_unique` on the map at ffffe54c (cell 0x8b6860, @0x8b617c), the second map at ffffe550 (cell 0x8b6868, @0x8b6204), and `std::__1::__hash_table<u64>::__erase_unique` at ffffe584 (cell 0x8b686c, @0x8b6284).\n- == 0xe (FreeBlock): reads ivar ffffe588 (cell 0x8b6874) and `[obj pos]` (cell 0x8b6870 ffe23298) -> `worldIndexAtWorldPos(intpair, World*)` (C call 0x8b636c) -> `std::__1::__tree<pair<u64, set<DynamicObject*>>>::__erase_unique` (0x8b6394).\nPositional registries: `objectTypeHasStaticPosition(int)` (C call 0x8b63c8); when true the position map at ffffe554 (cell 0x8b6880, 12-byte stride) + worldIndexAtWorldPos -> `std::__1::__tree<pair<u64,DynamicObject*>>::__erase_unique` (0x8b64f8). `objectTypeRequiresPartialUpdate(int)` (C call 0x8b652c); when true the 12-segment map at ffffe58c (cell 0x8b688c) erases the type segment (@0x8b65f8+). Finally the object is removed from the tile's own list: `std::__1::remove<vector<DynamicObject*>>` (C++ call 0x8b6658) + `std::__1::vector<DynamicObject*>::erase` (0x8b672c), and the unloading hook (cell 0x8b6890 ffe2326c) runs at 0x8b6734. Epilogue 0x8b67f0.\n"),
    ),
    dict(
        name='wtl_worldchangedatpos_send',
        method='DynamicWorld -[worldChangedAtPos:sendReliably:]',
        types='v20@0:4{?=ii}8c16',
        start=9303972,
        end=9307244,
        disasm='disasm_worldtileloader_worldchangedatpos_sendreliably_.txt',
        base_add=9303992,
        base_literal=9307240,
        boundary='ARM.exidx end 0x008e046c (listing bound); next ObjC IMP 0x008e046c DynamicWorld -[worldContentsChangedAtPos:]',
        selectors={},
        imports={},
        ivars={
                 0x8e0458: (17162412, 'OBJC_IVAR_$_DynamicWorld.worldChangedPositions', 6072),
                 0x8e045c: (17162340, 'OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions', 7320),
                 0x8e0460: (17162344, 'OBJC_IVAR_$_DynamicWorld.worldChangedSendUnreliablyMacroPositions', 6084),
        },
        classes={},
        instructions=[(9303972, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9304144, 'ldr r3, [0x008e0458]'), (9304252, 'ldr r0, [fp, -0x9c]'), (9304776, 'movw r0, 0x20'), (9304840, 'bl sym.makeIntpair_int__int_'), (9305296, 'add r0, sp, 0xc8'), (9306460, 'add r0, sp, 0x1f8'), (9307240, 'rsbseq r0, r8, r4, lsr r3')],
        calls=[(9304768, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_'), (9304796, 'bl sym.imp.__aeabi_idiv'), (9304816, 'bl sym.imp.__aeabi_idiv'), (9304840, 'bl sym.makeIntpair_int__int_'), (9305604, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_'), (9306200, 'bl sym.imp.__aeabi_memmove'), (9307200, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_')],
        branches=[(9304304, 'beq', 9304448), (9304352, 'bne', 9304384), (9304368, 'bne', 9304384), (9304380, 'b', 9304448), (9304384, 'b', 9304388), (9304444, 'b', 9304132), (9304456, 'bne', 9304776), (9304548, 'beq', 9304760), (9304696, 'beq', 9304740), (9304756, 'b', 9304772), (9304772, 'b', 9304776), (9305128, 'beq', 9305272), (9305176, 'bne', 9305208), (9305192, 'bne', 9305208), (9305204, 'b', 9305272), (9305208, 'b', 9305212), (9305268, 'b', 9304956), (9305280, 'bne', 9307216), (9305292, 'beq', 9306460), (9305384, 'beq', 9305596), (9305532, 'beq', 9305576), (9305592, 'b', 9305608), (9305884, 'beq', 9306456), (9305932, 'bne', 9306392), (9305948, 'bne', 9306392), (9306284, 'beq', 9306380), (9306376, 'b', 9306268), (9306388, 'b', 9306456), (9306392, 'b', 9306396), (9306452, 'b', 9305712), (9306456, 'b', 9307212), (9306736, 'beq', 9306880), (9306784, 'bne', 9306816), (9306800, 'bne', 9306816), (9306812, 'b', 9306880), (9306816, 'b', 9306820), (9306876, 'b', 9306564), (9306888, 'bne', 9307208), (9306980, 'beq', 9307192), (9307128, 'beq', 9307172), (9307188, 'b', 9307204), (9307204, 'b', 9307208), (9307208, 'b', 9307212), (9307212, 'b', 9307216)],
        semantics=("worldChangedAtPos:sendReliably: marks a world position (and its macro tile) as changed. Prologue 0x008df7a4 (frame 0xc8+0x400; base 0x105faf4). Arguments: pos pair [-0x128 region], self [fp,-0xbc area]; sendReliably byte at [sp,0xf7].\nExact-position dedup: a local `vector<intpair>` state at [sp,0xf0] iterates the vector inside ivar ffffe5b8 (cell 0x8e0458, @0x8df850): the comparison loop at 0x8df8bc-0x8df97c sets the found flag [sp,0xf6]; a new pair is appended (slow path __push_back_slow_path at 0x8dfab8) into the ffffe5b8 vector.\nMacro pair: the position is divided by 32 (`movw r0, 0x20` + `__aeabi_idiv` at 0x8dfac8-0x8dfaf0) and packed with `makeIntpair(int, int)` (C call 0x8dfb08).\nQueue push: when sendReliably ([sp,0xf7]) is set the macro pair is deduped (a second vector state at [sp,0xc0]) and pushed into the worldChangedMacroPositions vector inside ffffe570 (cell 0x8e045c, @0x8dfcd0-0x8dfdfc, slow path 0x8dfdfc); the else path and the second queue converge on the vector inside ffffe574 (cell 0x8e0460, @0x8dfe08 and 0x8e015c) with its own push (0x8e0440). Epilogue 0x8e0450.\nBoundary: the dual dedup micro-order around the sendReliably gate (the 570 vs 574 vectors) is recorded as observed; the queue split matches saveAndSendOnlyBlocksThatNeedToBeSent's two passes (E21).\n"),
    ),
    dict(
        name='wtl_clientconnected_',
        method='DynamicWorld -[clientConnected:]',
        types='v12@0:4@8',
        start=9401384,
        end=9404304,
        disasm='disasm_worldtileloader_clientconnected_.txt',
        base_add=9401400,
        base_literal=9404300,
        boundary='ARM.exidx end 0x008f7f90 (listing bound); next ObjC IMP 0x008f8108 DynamicWorld -[stopAllBlockheadActionsForClientDueToKick:]',
        selectors={
                 0x8f7f2c: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8f7f34: (15215996, 'removeObject:'),
                 0x8f7f3c: (15216144, 'array'),
                 0x8f7f44: (15216280, 'isEqualToString:'),
                 0x8f7f48: (15216440, 'clientID'),
                 0x8f7f4c: (15216104, 'inventoryNeedsSaving'),
                 0x8f7f50: (15216100, 'prepareInventoryForSaving'),
                 0x8f7f54: (15216112, 'setInventoryNeedsSaving:'),
                 0x8f7f58: (15216108, 'saveBlockheadInventory:'),
                 0x8f7f5c: (15216008, 'addObject:'),
                 0x8f7f60: (15216528, 'setNeedsRemoved:'),
                 0x8f7f64: (15215864, 'count'),
                 0x8f7f68: (15216116, 'saveBlockheads'),
                 0x8f7f6c: (15216468, 'removeFromMacroBlock'),
                 0x8f7f70: (15215844, 'blockheadWillBeUnloaded:'),
                 0x8f7f74: (15216616, 'notifyPlayersChanged'),
                 0x8f7f7c: (15217116, 'usedPhysicalBlocks'),
                 0x8f7f84: (15216332, 'loadClientOwnedDynamicObjectsForClient:physicalBlock:'),
        },
        imports={
                 0x8f7f28: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f7f30: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
                 0x8f7f38: (17162400, 'OBJC_IVAR_$_DynamicWorld.disconnectedClientsSaveDirNames', 9468),
                 0x8f7f78: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
                 0x8f7f80: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={
                 0x8f7f40: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(9401384, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9401472, 'ldr r5, [0x008f7f30]'), (9401608, 'blx r2'), (9401868, 'ldr r3, [0x008f7f44]'), (9402708, 'ldr r0, [sp, 0x88]'), (9403228, 'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.unordered_set_std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock____const_'), (9403988, 'ldrsb r1, [r1, 0xc]'), (9404000, 'ldr r0, [fp, -0x180]'), (9404300, 'ldrhteq r8, [r6], -0x64')],
        calls=[(9401608, 'blx r2'), (9401652, 'blx ip'), (9401684, 'bl sym.imp.memset'), (9401748, 'blx lr'), (9401848, 'bl sym.imp.objc_enumerationMutation'), (9401940, 'blx ip'), (9401960, 'blx r3'), (9402036, 'blx ip'), (9402056, 'blx r2'), (9402148, 'blx lr'), (9402176, 'blx r3'), (9402260, 'blx r4'), (9402296, 'blx r3'), (9402408, 'blx ip'), (9402476, 'blx r2'), (9402584, 'blx r2'), (9402604, 'bl sym.imp.memset'), (9402652, 'blx lr'), (9402752, 'bl sym.imp.objc_enumerationMutation'), (9402884, 'blx r5'), (9402904, 'blx r2'), (9402944, 'blx ip'), (9403044, 'blx ip'), (9403132, 'blx r2'), (9403208, 'blx r3'), (9403228, 'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___.unordered_set_std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock____const_'), (9404028, 'bl loc.imp.objc_msgSend'), (9404056, 'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___._unordered_set__'), (9404072, 'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___._unordered_set__'), (9404160, 'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___._unordered_set__'), (9404176, 'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___._unordered_set__'), (9404196, 'bl sym.imp._Unwind_Resume')],
        branches=[(9401432, 'beq', 9404184), (9401760, 'beq', 9402432), (9401840, 'beq', 9401852), (9401972, 'beq', 9402308), (9402068, 'beq', 9402180), (9402308, 'b', 9402312), (9402336, 'blo', 9401804), (9402428, 'bne', 9401804), (9402432, 'b', 9402436), (9402484, 'bls', 9403136), (9402664, 'beq', 9403068), (9402744, 'beq', 9402756), (9402972, 'blo', 9402708), (9403064, 'bne', 9402708), (9403068, 'b', 9403072), (9403940, 'beq', 9404156), (9403944, 'b', 9403948), (9403996, 'beq', 9404084), (9404032, 'b', 9404036), (9404036, 'b', 9404084), (9404080, 'b', 9404192), (9404084, 'b', 9404088), (9404152, 'b', 9403792)],
        semantics=("clientConnected: wires a newly connected client: matches its blockheads, prunes stale ones and pushes every dirty physical block. Prologue 0x008f7428 (frame 0x400+0x18; base 0x105faf4). Argument: the client object [-0x188]; gate != 0 else exit 0x8f7f18.\nPass 1 (0x8f745c-0x8f783c): enumerate the collection ivar ffffe4f0 (cell 0x8f7f30, @0x8f7480) with countByEnumeratingWithState: (cell 0x8f7f2c ffe231ec); per item: class check (isKindOfClass: cell 0x8f7f3c ffe2331c, class cell 0x8f7f40 ffe2aeb0 at 0x8f74dc), an argument method yielding the BOOL [fp,-0x18d] (via the cell-0x8f7f38 ffffe5ac ivar slot call at 0x8f7508-0x8f7534); per element: `[item clientID]` (cell 0x8f7f48 ffe23444) compared with the argument pair; on match the calls at 0x8f760c-0x8f7784 run (cells ffe233a4, ffe232f4/ffe232f0, ffe232fc/ffe232f8, ffe23294 add-style with 1, ffe2349c sxtb flag) and the BOOL result is re-stored (0x8f77b8).\nPass 2 (0x8f7844-0x8f7abc): re-enumerate ffffe4f0 with the sel cell 0x8f7f68 ffe23300 (a connection/liveness getter): when the gate fails the item is removed - `removeObject:` (cell 0x8f7f34 ffe23288), cell 0x8f7f6c ffe23460, `blockheadWillBeUnloaded:` (cell 0x8f7f70 ffe231f0) with the count-2 marker @0x8f7954-0x8f7aa8.\nDirty-block push (0x8f7ac0-0x8f7f18): `[self.world (ffffe4e4, cell 0x8f7f80) sel ffe236e8 (cell 0x8f7f7c)]` returns the world's `std::unordered_set<PhysicalBlock*>` which is copy-constructed (C++ call 0x8f7b5c); a packed structure (float 1.0 via vmov.f32 s0, the counters/flags at [fp,-0x90..]) is assembled and the set is iterated: per block the byte at [block+0xc] must be nonzero (dirty gate, @0x8f7e54) before the call `[self cell-0x8f7f84 ffe233d8 : block arg]` at 0x8f7e60-0x8f7e80 - every dirty physical block is handed to the new client. Epilogue row at 0x8f7f88/0x8f7f8c (the two base-anchor cells); exit 0x8f7f18.\n"),
    ),
]


def signed(v: int) -> int:
    return v - (1 << 32) if v & 0x80000000 else v


def bl_target(site: int, word: int) -> int:
    if word >> 24 != 0xEB:
        raise ValueError(f'{site:#x} is not ARM bl')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xffffffff


def recover(path: Path) -> dict:
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA:
        raise ValueError('unsupported ELF SHA-256; fixed-IMP analysis requires pinned original')
    memory = ELFMemory(path)
    elf = ELFFile(io.BytesIO(data))

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = data.find(b'\0', off, off + 256)
        return data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    dynsym = {}
    for sec in elf.iter_sections():
        if sec.name == '.dynsym':
            for s in sec.iter_symbols():
                if s['st_value']:
                    dynsym.setdefault(s['st_value'], s.name)
    relocs = {}
    for sec in elf.iter_sections():
        if not isinstance(sec, RelocationSection):
            continue
        syms = elf.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            if r['r_info_sym']:
                relocs[r['r_offset']] = syms.get_symbol(r['r_info_sym']).name

    methods = []
    for spec in SPECS:
        text = (NATIVE / spec['disasm']).read_text()
        words = verify_disassembly(memory, text, spec['start'], spec['end'])
        rows = {}
        for mm in re.finditer(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', text):
            rows[int(mm.group(1), 16)] = mm.group(2).split(';')[0].strip()

        base = None
        if spec['base_add'] is not None:
            base = (spec['base_add'] + 8 + signed(memory.word(spec['base_literal']))) & 0xffffffff
            if base != EXPECTED_BASE:
                raise ValueError(f"{spec['name']}: PIC base drift {base:#x}")

        selectors = {}
        for cell, (expected_slot, expected_name) in spec['selectors'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: selector cell {cell:#x} -> {slot:#x}")
            got = cstr(memory.word(slot))
            if got != expected_name:
                raise ValueError(f"{spec['name']}: selector drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'selector': got}

        for cell, (expected_slot, expected_symbol) in spec.get('classes', {}).items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: class cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            if entry is None:
                got = relocs.get(slot, '')
                if got != expected_symbol:
                    raise ValueError(f"{spec['name']}: class reloc drifted at {cell:#x}: {got!r}")
                selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got,
                                              'route': 'ABS32 relocation symbol'}
                continue
            got = dynsym.get(entry, '')
            if got != expected_symbol:
                raise ValueError(f"{spec['name']}: class drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got,
                                          'route': 'dynsym entry at slot word'}

        for cell, (expected_slot, expected_name) in spec['imports'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: import cell {cell:#x} -> {slot:#x}")
            got = memory.imports.get(slot)
            route = 'PLT/GOT relocation (R_ARM_JUMP_SLOT / GLOB_DAT)'
            if got is None:
                got = relocs.get(slot)
                route = 'ABS32 relocation symbol'
            if got != expected_name:
                raise ValueError(f"{spec['name']}: import drifted at {cell:#x}: {got!r} ({route})")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got, 'route': route}

        ivars = {}
        for cell, (expected_slot, expected_symbol, expected_offset) in spec['ivars'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: ivar cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            symbol = dynsym.get(entry, '')
            offset = memory.word(entry)
            if symbol != expected_symbol or offset != expected_offset:
                raise ValueError(f"{spec['name']}: ivar {cell:#x} drifted: {symbol!r}@{offset}")
            ivars[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'symbol': symbol, 'offset': offset}

        inrange = {a: ins for a, ins in rows.items() if spec['start'] <= a < spec['end']}
        listed = {a for a, ins in inrange.items() if re.match(r'^blx?\s', ins)}
        expected_sites = {site for site, _ in spec['calls']}
        if listed != expected_sites:
            raise ValueError(f"{spec['name']}: call set drifted: {sorted(listed ^ expected_sites)}")
        calls = []
        for site, route in spec['calls']:
            if rows[site] != route:
                raise ValueError(f"{spec['name']}: route drifted at {site:#x}: {rows[site]!r}")
            target = None
            if route.startswith('bl '):
                target = bl_target(site, memory.word(site))
                expected = ROUTE_TARGETS.get(route)
                if expected is None or target != expected:
                    raise ValueError(f"{spec['name']}: bl target drifted at {site:#x}: {target:#x}")
            calls.append({'site': f'0x{site:08x}', 'route': route,
                          'callee': f'0x{target:08x}' if target else None})

        listed_branches = set()
        disjoint = []
        for a, ins in inrange.items():
            m = re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)
            if not m or m.group(1) in ('bl', 'blx'):
                continue
            dest = int(m.group(2), 16)
            if spec['start'] <= dest < spec['end']:
                listed_branches.add((a, m.group(1), dest))
            else:
                disjoint.append({'address': f'0x{a:08x}', 'mnemonic': m.group(1),
                                 'destination': f'0x{dest:08x}'})
        expected_branches = {(a, mn, dest) for a, mn, dest in spec['branches']}
        if listed_branches != expected_branches:
            raise ValueError(f"{spec['name']}: branch set drifted: {sorted(listed_branches ^ expected_branches)}")

        for address, expected_text in spec['instructions']:
            if rows.get(address) != expected_text:
                raise ValueError(f"{spec['name']}: instruction drifted at {address:#x}: "
                                 f"{rows.get(address)!r} != {expected_text!r}")

        methods.append({
            'name': spec['name'],
            'method': spec['method'],
            'types': spec['types'],
            'imp': f"0x{spec['start']:08x}",
            'boundary_end': f"0x{spec['end']:08x}",
            'boundary': spec['boundary'],
            'verified_words': words,
            'pic_base': f'0x{base:08x}' if base else None,
            'selectors': selectors,
            'ivars': ivars,
            'calls': calls,
            'branches': [{'address': f'0x{a:08x}', 'mnemonic': mn,
                          'destination': f'0x{d:08x}'}
                         for a, mn, d in spec['branches']],
            'disjoint_branch_rows': disjoint,
            'semantics': spec['semantics'],
        })

    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': 'DynamicWorld world-save cluster (E22): saveGameWithWorldData:signOwnershipData: (five-container dirty sweep), saveBlockheads, saveDynamicObjectsForMacroTile:objectType:xPos:yPos:, removeDynamicObjectsForMacroTile:, worldChangedAtPos:sendReliably: and clientConnected:; 6 bodies',
        'claim': ('a static bounded-body map with per-instruction anchors; the wire-format markers, the '
                  'NSLog key strings, the C++ container member layouts and the packet helper at 0x8b84c8 are '
                  'outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_save.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_save.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
