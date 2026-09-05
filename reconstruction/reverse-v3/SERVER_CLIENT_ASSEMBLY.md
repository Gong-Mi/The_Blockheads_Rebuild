# Server sample -> production client decoder assembly

## Executed boundary

Original Linux server 1.7.1 SHA256
`b1534f723ac524e1ed283e1cad01bb8cdfb6caf03c98642e25730266f0cfd5ea`.
The stopped local experimental world `reverse-probe-001` provided 40 physical
block records. No original game binaries or generated world payloads are added
to git. `tools/test_server_save_client.py` reads every record in `blocks`, then
builds `tools/decode_original_block.cpp` against the actual client
`app/src/main/cpp/original_save_format.cpp`. It does not reimplement that decoder.

O0 and O2: all 40 records decode and reproduce the entire 65541-byte payload,
including all 1024 raw Tile structures and both appended fields, byte-for-byte
against Python gzip. For each record and optimization level the executable also
rejects empty input, truncation, CRC corruption, short and long inflated payloads.
This is characterization/integration coverage of existing code, not historical
RED/GREEN and not a new recovered gameplay method. Existing
`test_original_save_format.cpp` also passes at O2.

Run with the server STOPPED (lock=False is deliberately only for offline reads):

    python3 tools/test_server_save_client.py /absolute/world_db --report /absolute/report.json

Dependencies: Python lmdb, clang++, zlib. On Termux use the packaged liblmdb with
`LMDB_FORCE_SYSTEM=1` when building Python lmdb; its bundled LMDB attempts APIs
for robust pthread mutexes unavailable here. The report is required, all record
keys and hashes are preserved; no-record input fails instead of passing vacuously.

## New source evidence

`tools/recover_server_tile.py` verifies the server ELF hash and extracts the
complete 26-member Tile declaration at DWARF DIE 0x41129. The resulting
`server_tile_dwarf.json` records offset, type chain and size. The server structure
is 64 bytes. Particularly offset 7 is `sunLight`, offset 20 is `artificialHeat`;
current client accessor names `temperatureScaleByte` and `temperatureOffset`
are not exact server source names. Cross-check ARM 1.7.6 consumers before renaming;
matching payload size alone is not a cross-version semantic proof.

## Expanded offline assembly and regression gate

`export_server_world.py` archives every physical file plus every named-database
record, preserving binary keys as hex and values as SHA256-addressed blobs.
`restore_world()` restores only into a new directory, rejects unsafe paths and
checks all file hashes. `test_export_server_world.py` covers binary keys, empty
databases, opaque files, exact file restoration, corruption, overwrite rejection
and path traversal rejection.

Actual experimental archive: 11 physical files, three LMDB environments, five
named databases and 53 records. `assemble_server_snapshot.py` invokes the compiled
production decoder on 40 blocks and parses all remaining 13 records as plist;
16 dynamic objects are preserved without guessing their runtime class from keys.
The resulting JSON is an inspection view; the original bytes remain in the
archive. Do not treat this JSON as the original serialization or a gameplay world.

Restored all physical files into a separate experiment root and started the
original server with that root: same seed 1788626619, `World load complete.`.
The process was stopped afterwards. This verifies archive->original reload,
not Android client whole-world import.

CMake now builds the six existing full-method tests, five numerical-slice tests,
and the production save decoder test together. Debug and Release both execute
12/12 tests successfully. Assert-based tests explicitly use -UNDEBUG in Release.
The host decoder CLI is also part of this build. These are local CPU tests,
not Android exact-head CI or physical graphics acceptance.

## Complete server types and resolved transport blocker

`recover_server_types.py` scans all DWARF compilation units of the hash-pinned
original server. It merges 1120 definitions after exact structural/value checks:
Tile and PhysicalBlock plus all 53 named enums, 1817 enumerators. Counts include
TileType=78, ItemType=428, TileContents=149, DynamicObjectType=66. The independent
unit test traverses every original definition again and checks all member
names/offsets and enum names/values. Eight tests pass with the original ELF.
PhysicalBlock is 328 bytes in Linux x86-64, NOT the ARM32 layout; pointer fields
must never be copied as an Android structure.

ENet blocker resolved with local A/B: the earlier probe unconditionally enabled
range-coder compression, while the server did not. Enabled: repeated 34-byte
CONNECT datagrams, no response. Disabled: 52-byte initial datagram, CONNECT event
and a 243-byte application message. The complete application bytes start with
0x23 0x26, followed by an XML plist containing worldID=reverse-probe-001. This is
one observed message shape, not a universal framing specification.

`tools/probe_local_server.c` defaults to uncompressed transport, restricts target
to loopback and prints complete application payloads. Compiled with
`clang -Wall -Wextra -Werror ... -lenet` and exercised against the local restored
world on UDP15169; CONNECT and matching worldID verified. The original compression
A/B and packet captures remain outside the repo in blockheads-work/enet-analysis.
92 wire-layout/constant assertions matched the installed ENet headers. Original
and dependency-patched server comparisons verified 96 ENet/server-start function
bodies unchanged, accounting for patchelf's file-offset relocation.

Game-level player-information exchange, authentication and Android1.7.6 joining
have NOT yet been verified. Do not infer them from successful ENet transport.
Local UBSan-trap build additionally passes all 12 CTest targets.

## Assembly state and next boundary

    original server generation/save
      -> offline LMDB blocks enumeration (Python)
      -> actual production C++ gzip decoder (host executable)
      -> complete raw Tile arrays + appended fields [VERIFIED]
      -> client world/chunk ownership [NOT INTEGRATED]
      -> renderer/gameplay/lifecycle [NOT VERIFIED]

Do not flatten these records into the prototype world.bin or assign invented
material/atlas identities. A whole-world importer needs coordinate semantics,
missing-chunk policy, dynamic-object records and world metadata. Those are not
proved by this block decoder test. `dw` and `main` are real named databases, not
physical files. ENet transport now connects without compression; game-level
player-information exchange remains an independent pending lane.
