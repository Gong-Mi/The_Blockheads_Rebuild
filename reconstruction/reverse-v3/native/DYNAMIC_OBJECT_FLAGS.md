DynamicObject flag and owner accessors

Original ELF SHA-256:

`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Bounded ARM32 range:

`0x0083d0f0..0x0083d370`

Recovered directly from the fixed implementation range:

- `-[needsRemoved]` → bool, ivar offset `self + 0x30`
- `-[setNeedsRemoved:]` → bool store, ivar offset `self + 0x30`
- `-[updateNeedsToBeSent]` → bool, ivar offset `self + 0x31`
- `-[setUpdateNeedsToBeSent:]` → bool store, ivar offset `self + 0x31`
- `-[creationDataNeedsToBeSent]` → bool, ivar offset `self + 0x32`
- `-[setCreationDataNeedsToBeSent:]` → bool store, ivar offset `self + 0x32`
- `-[unreliableUpdateNeedsToBeSent]` → bool, ivar offset `self + 0x33`
- `-[setUnreliableUpdateNeedsToBeSent:]` → bool store, ivar offset `self + 0x33`
- `-[isNet]` → bool, ivar offset `self + 0x34`
- `-[macroTileOwner]` → pointer, ivar offset `self + 0x0c`

The five getter bodies use signed-byte loads. The four setters use byte stores with the observed ARM DMB barriers. `macroTileOwner` uses a pointer load followed by the observed barrier.

This is static bounded recovery only. It does not claim dynamic entity construction, save schema completion, APK integration, or runtime equivalence.
