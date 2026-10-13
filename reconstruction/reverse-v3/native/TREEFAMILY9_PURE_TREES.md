# treefamily9 pure trees — GetSaveDict / load-side shape evidence (2026-09-28)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Why: MapleTree (2), MangoTree (3), CherryTree (8), CoffeeTree (9) and
LimeTree (37) were the last treefamily9 classes without a registered
loader. This note pins the evidence that their complete save-record key
domain is the inherited Tree chain — no own keys on either side.

## Load side: no own reader

The pinned method map (`libApplication_objc_methods.tsv`) carries ZERO
`loadSaveDictValues:` rows for these five classes (GemTree and CactusTree
are the only treefamily9 classes with their own — both already covered by
the b3b read-back tables). Their `initWithWorld:...:treeDensityNoiseFunction:`
initialisers are the treefamily9 first-seen batch's byte-identical 62-word
forwarders (no CFString key read, no ivar written, no post-init hook;
`treefamily9_long_initwithworld.json`).

## Save side: the 31-word pure-forward GetSaveDict

GetSaveDict bodies (IMP -> next-IMP word counts from the same map):

| class | IMP | words | full-body sha256 (first 32) |
|---|---|---:|---|
| OrangeTree (7, registered) | 0x00a966fc | 31 | be3931695ea10363f1b9c54b482d8a5b |
| CoconutTree (registered) | 0x00a99ab4 | 31 | cff3ea8876dcb097a020da0ba9b22e58 |
| CherryTree (8) | 0x00d0e024 | 31 | 9a1c8df4dc6347701c035ed24da37118 |
| MangoTree (3) | 0x00d4b5ec | 31 | c2e463543eb1c9376a7d455c259a242d |
| MapleTree (2) | 0x00db60ac | 31 | a56c49952e14ade8d249611a155d051c |
| CoffeeTree (9) | 0x007dec20 | 32 | 950c23c3f4c304557a1d9c33c3a2ef00 |
| LimeTree (37) | 0x00809d34 | 31 | e10850965d407c564aca3e66e40d952d |

The first 25 words (the whole code body; the tail words are the per-class
literal cells) are **byte-identical across all seven**, sha256 of the
25-word core:

`af5a10bb83973043a15b66c336f99b112a3c348d0c8234e2cec88d0129d2a30c`

For contrast, the classes with own save keys have larger bodies and
different shapes: AppleTree 78 (~availableFood@136), PineTree 79, GemTree
112 (gemTreeType/fruitYear), CactusTree 202 (splitHeight*+availableFood).

Since OrangeTree and CoconutTree are already registered with the Tree
chain only, and the five remaining classes share their exact save-side
body (25-word core sha-gated) plus the same zero-own-key load side, their
full key domain equals Tree's and they register on the same standard.

Reproduce: `tools/test_tree9_pure_trees_evidence.py [--elf <pinned ELF>]`
— recomputes the hashes when the ELF is given, otherwise asserts the
recorded constants (CI-safe).
