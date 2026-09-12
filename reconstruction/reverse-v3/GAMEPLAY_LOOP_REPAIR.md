# Gameplay-loop repair: production integration, not original-method completion

Baseline: `641db83dc73fb1b884cd946361ed982d4c6166ef` on `reverse-v3`.

## Scope and attribution

This batch changes the actual APK gameplay sources, rather than only a protocol
probe or an independently linked recovered-method library. It repairs confirmed
breaks in the existing replacement runtime. It does **not** add an original
method to the `implemented_methods.json` ledger, recover mining timing, establish
recipe fidelity, or convert development `world.bin` into original LMDB saves.
The existing type/atlas mapping, pathfinding, movement, seed generation, and
simulation timing remain replacement behavior.

Original cross-check: Android 1.7.6 ELF SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`;
`Blockhead::pickupFreeblockIfPossible:inTile:intentional:` starts at `0x00c61c00`,
with `.ARM.exidx` end `0x00c638a0`. Its capacity route at `0x00c627f0` calls the
pickup classifier and `0x00c627f4..0x00c627f8` compares its integer return with
exactly 1, branching away otherwise. It is not an `addItemToInventory` returned
count check. See `CONTENT_ACTION_EVIDENCE.md` for the other original dependencies:
subItems, dataA/dataB, priority, ownership, simulation and network effects. The
replacement's accepted-count interface is an explicit safety adaptation for its
plain type/count inventory, **not** a recovered signature or full-method port.

## Production changes

- `BlockheadAI::update`: retain mining action until the tile is actually removed
  (or no target exists). The previous independent progress>=100 clock popped the
  action before damage reached its removal threshold. Existing damage rates and
  drop-generation cases remain unchanged. Preserve target coordinates before
  popping; do not use the invalidated queue reference.
- Placement preserves the existing 16-bit `Tile.foreground` representation;
  the old uint8 cast changed item 270 into another number.
- `GameWorld::refreshTileMesh`: successful mine/place edits recompute lighting
  once and rebuild all loaded CPU chunk meshes, setting `meshReady`. A torch on
  a chunk boundary changes neighboring lighting too; rebuilding only its own
  chunk left neighboring VBOs stale. The placement test covers both adding and
  removing this light source across a chunk boundary. Merely changing tiles or
  dirty flags was insufficient: the camera only queued missing chunks. This is
  synchronous, not an optimized scheduler or performance claim. Existing
  worker/publication concurrency is not comprehensively repaired.
- `GameWorld::getTileInternal`: reject negative Y before integer division;
  -1/32 previously truncated to chunk zero, indexing before the Tile array.
  The two-chunk light test exposed an actual UBSan trap; with the guard, the
  same test and all seven gameplay CTests pass in O1 UBSan-trap mode.
- `Player::addItem` returns the actual accepted quantity and refuses nonpositive
  types/counts. The 99-stack rule and slot ordering remain the existing policy.
- `EntityManager::update`: remove a one-item drop and emit pickup sound/dirty
  state only if one item was accepted. Full inventory leaves the drop alive.
- `CraftingManager`: materials are still paid once at start; timer completion
  and delivery completion are distinct. Full/partial inventory keeps remaining
  output in the active task; retry never duplicates delivered units or recharges
  materials. The update result reports real inventory changes.
- `GameActivity::onDrawFrameNative`: consumes that result to mark inventoryDirty,
  letting the existing JNI hotbar update path publish crafted items.

## Reproduction and executed evidence

Run from the repository root (all build outputs outside the source tree):

    cmake -S reconstruction/recovered -B /absolute/build-O0 \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE='-O0 -DNDEBUG'
    cmake --build /absolute/build-O0 --parallel 2
    ctest --test-dir /absolute/build-O0 --output-on-failure

Repeat with `-O2` and a different build directory. The existing GitHub Android
workflow already runs this root at both levels; the new gameplay subdirectory
joins that same batch. No additional full Android matrix is introduced.

Observed local results: O0 and O2 each execute 19/19 CTest targets. Of these,
seven are new gameplay targets (mining, pickup, placement, loop, rejected actions,
inventory, crafting delivery); the crafting executable separately runs seven
named scenarios. All use real production world/inventory/action/crafting sources
and the project's generated item/recipe data. Assertions stay enabled in Release.

The initial regression binary failed on mining-without-removal, full-bag drop
loss, 16-bit placement truncation, and the combined loop. The unchanged empty
and unavailable-item rejection characterization passed. After repairs, all pass.
The combined test uses the actual produced drop, accepts it through the real
entity update, places it at a different tile, saves the changed world with the
existing development serializer, and reloads it with the actual loader. It checks
all raw tile and inventory bytes and reconstructed mesh readiness. The fixture
stops the world's worker and positions the drop at the pickup boundary: it is
not a pathfinding, physics trajectory, threading, JNI, GLES or human-input test.

Android logging is selected only on Android; host persistence tests use stderr.
This permits Linux CI to exercise the same serializer instead of mocking it.

## Remaining boundaries

- Original action selection, path/reach constraints, ordinary/special item
  semantics, crafting benches and recipes are not restored by these fixes.
- Pending crafts and world drops remain in-memory runtime state; existing
  development persistence does not save them. Only the completed pickup/place
  state is covered by this round trip; mid-craft/full-bag save/restart is NOT
  verified or fixed here.
- CPU mesh readiness does not prove GPU upload or visual correctness. Android
  construction and APK content verification are separate GitHub CI evidence.
- No installation, foreground launch, touch injection, screenshot, original-app
  runtime differential or physical-device gameplay acceptance in this batch.
- Exact pushed SHA/run/artifact outcomes belong in PR #1 after reading the real
  CI logs. Local PASS must not be reported as remote PASS.
