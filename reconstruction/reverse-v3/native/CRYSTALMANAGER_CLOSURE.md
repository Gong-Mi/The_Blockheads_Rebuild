# CrystalManager closure (E10) — the crystal store the trade portal fingerprints

Closes `CrystalManager` (13 methods; `-loadFromSave` is the b4i batch's and stays
with it). All 12 bodies below are statically recovered from the SHA-256-pinned
original `libApplication.so` (1.7.6, armeabi-v7a,
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`) and re-verified
word by word by `tools/recover_crystalmanager_closure.py` (**12 bodies, 1305
instruction words**). The artifact is `native/crystalmanager_closure.json`; the
tool refuses to emit when any instruction word, PIC-base literal, cell target,
call target or branch destination drifts.

This batch is the other half of the crystal path: E9b recovered the trade portal
consumer (`-takeItemsFromBlockheadForUpgradeToNextLevel`), which calls
`[CrystalManager instance]`, reads `amount` / `amountString`, MD5-fingerprints the
amount string and then calls `modify:modifyString:`. Here the store side is pinned,
including the two format strings and the literal salt the fingerprints are built from.

## Store shape

The ivars the whole class is built on, each confirmed through its own literal-pool
cell (offsets are the raw `OBJC_IVAR_$_CrystalManager.*` values, so they are
independent of any struct guess):

| ivar | offset | read by | written by |
|---|---:|---|---|
| `saveQueue` | 4 | `commitSaveIfNeeded:` | `-init` (`[[NSOperationQueue alloc] init]`) |
| `crystalCount` | 8 | `-amount`, `modify:modifyString:` | `modify:modifyString:` (`-= amount`) |
| `amountString` | 12 | `-amountString` (dmb ish) | `modify:modifyString:` |
| `countWatcher` | 16 | `-countWatcher` (dmb ish) | `-setCountWatcher:` (dmb ish pair) |
| `needsSave` | 20 | `-needsSave` (ldrsb), `-commitSaveIfNeeded:` | `-save` (= 1), `-commitSaveIfNeeded:` (= 0) |

## Singleton and lifecycle

`+instance` (0x009f3b14, 50w) is a plain lazy singleton over the static slot
0x01064984: the nil test at 0x009f3b40 returns the existing object at 0x009f3bb8, and
the cold path dispatches `[[CrystalManager alloc] init]` (class cell 0x009f3bd4,
`alloc` cell 0x009f3bd0 at 0x009f3b90, `init` cell 0x009f3bcc at 0x009f3ba0) and
stores the result back (0x009f3ba8). No lock and no barrier: the singleton is
single-threaded by construction.

`-init` (0x009f3bdc, 90w) calls `objc_msgSendSuper2` init (0x009f3c30), returns nil
for a nil self (0x009f3c54), and otherwise builds the class's serial background
queue: `saveQueue@4 = [[NSOperationQueue alloc] init]` (class cell 0x009f3d3c at
0x009f3cc0/0x009f3cd0, stored through the ivar cell 0x009f3d34 at 0x009f3ce4)
followed by `[saveQueue setMaxConcurrentOperationCount:1]` (0x009f3d08, argument 1
from 0x009f3c5c) — i.e. a serialized save pipeline, not a concurrent one.

The save flag is split across three bodies and is deliberately cheap on the caller
side: `-save` (0x009f4f34, 16w) only sets `needsSave@20 = 1` (0x009f4f40/0x009f4f60),
`-needsSave` (0x009f5fac, 15w) is the matching `ldrsb` (0x009f5fd4), and
`-commitSaveIfNeeded` (0x009f4568, 68w) is what actually does the work: it returns
immediately when the flag is clear (0x009f4598, `beq` 0x009f464c), clears the flag
(0x009f4600) and then enqueues a stack block on `saveQueue@4` through
`addOperationWithBlock:` (0x009f4648). The block literal is visible in the frame at
sp+8: `isa = _NSConcreteStackBlock` at [sp,8] (0x009f4614), flags word **0xc2000000**
at [sp,0xc] (0x009f4618 — `HAS_EXTENDED_LAYOUT | HAS_SIGNATURE | HAS_COPY_DISPOSE`;
the r2 listing misdecodes that pool word as an instruction), reserved 0, then the two
pointer slots: **invoke = 0x009f4678** at [sp,0x14] (0x009f4620 — delta cell 0x009f4664
resolves to base-0x6b47c, and the word at 0x009f4678 is 0xe92d4df0, the `push` prologue
of the block body) and **descriptor = 0x010524c0** at [sp,0x18] (0x009f4624 — delta cell
0x009f4660, first word 0 in the file), with `self` captured at [sp,0x1c] (0x009f462c).
The invoke address is the first byte after this method's own body, which is exactly the
non-method gap the boundary note below measures: the 2236 bytes between
`-commitSaveIfNeeded` and `-save` start with its own block implementation.

## Accessors

`-amount` (0x009f452c, 15w) is a bare load of `crystalCount@8` (0x009f4554) — no
call, no branch, no barrier. `-amountString` (0x009f5fe8, 17w) and `-countWatcher`
(0x009f5f24, 17w) are `dmb ish` loads of `amountString@12` (0x009f600c/0x009f6010)
and `countWatcher@16` (0x009f5f48/0x009f5f4c); `-setCountWatcher:` (0x009f5f68, 17w)
writes `countWatcher@16` between two `dmb ish` barriers (0x009f5f90/0x009f5f94/
0x009f5f98). The asymmetric pair (plain load for `crystalCount`, atomic for
`countWatcher`/`amountString`) is measured, not assumed: it is what the listings show.

## modify:modifyString: — the fingerprint contract

`modify:modifyString:` (0x009f4f74, 190w, `v16@0:4i8@12`) takes an int delta and a
fingerprint string, and refuses to touch the store unless the fingerprint matches:

1. it recomputes the expected string
   `[NSString stringWithFormat:@"7acfe93afc08c%d65ae2c54ecaf07f", crystalCount@8 - amount + 73]`
   — format cell 0x009f5240 (slot 0x00f96bf8), `+0x49` added at 0x009f500c, dispatch
   at 0x009f5030;
2. `[that stringFromMD5]` (selector cell 0x009f523c at 0x009f5040) is compared with
   the argument through `isEqualToString:` (cell 0x009f5238) at 0x009f505c —
   `sxtb`/`cmp`/`beq 0x9f522c` means **a mismatch returns without any store write**;
3. on a match it applies the delta: `crystalCount -= amount` (0x009f5144, stored
   0x009f514c);
4. it rebuilds `amountString@12` from the new count through the three dispatches at
   0x009f51b4 / 0x009f51c4 / 0x009f51d4 (selector cells `stringWithFormat:`
   0x009f5244, `stringFromMD5` 0x009f523c, `retain` 0x009f5260; the format string is
   `@"7acfe93afc08%dc65ae2c54ecaf07f"` at cell 0x009f5264 -> slot 0x00f96b68) and
   stores the result through the `amountString` ivar cell 0x009f525c at 0x009f51e8;
5. it notifies `[countWatcher@16 crystalCountChanged:1]` (selector cell 0x009f5254,
   watcher cell 0x009f5258, argument 1 from 0x009f5084, dispatch 0x009f5214) and
   calls `[self save]` (cell 0x009f5250 at 0x009f5228), which only sets the flag.

Steps 1–2 and 4 are what the E9b consumer exercises from the other side: the caller
pre-computes the same `7acfe93afc08c%d…` fingerprint over `newCount + 73` and passes
it in, and re-reads `amountString` (the `7acfe93afc08%d…` variant over the new count)
afterwards. Two format strings, two call sites, one scheme.

## iCloud identity

`-iCloudServerRejoinID` (0x009f5e78, 43w) is
`[[[self iCloudID] stringByAppendingString:@"rejoin"] stringFromMD5]`: the dispatch
chain is 0x009f5edc (`iCloudID`, cell 0x009f5f1c), 0x009f5ef0
(`stringByAppendingString:`, cell 0x009f5f18, with the CFString `@"rejoin"` — cell
0x009f5f14 -> `__CFConstantStringClassReference`, slot 0x00f96ce8, data pointer
0x00f5be3d, length 6) and 0x009f5f00 (`stringFromMD5`, cell 0x009f5f10). The rejoin id
is therefore a salted MD5 of the iCloud id, using the same literal-salt +
`stringFromMD5` idiom as the crystal amount fingerprint.

`-iCloudID` (0x009f526c, 767w — the largest body in the class: 47 selector-side
cells, 46 call sites, 27 branches) is the identity resolver, reading four independent
sources and keeping the one with the smallest 64-bit suffix:

1. **GDPR gate.** `[NSUserDefaults standardUserDefaults] integerForKey:@"gdprStatus"`
   (0x009f52e0) compared with 3 (0x009f52ec) returns `@"gdpr_declined"` early
   (0x009f5304) — the id is never read or written when the user declined.
2. **Legacy Keychain migration**, only when
   `+[NCKeychainCompatibility decryptDepricatedKeychain]` (0x009f536c, nil-check
   0x009f5380) answers: it builds a 4-entry query dictionary
   (`kSecAttrAccount`/`kSecAttrLabel`/`kSecAttrService` =
   `@"com.majicjungle.blockheads.cloudid2"`, `kSecClass` = `@"kSecClassGenericPassword"`;
   0x009f54d0 / 0x009f5524), reads
   `[[result objectForKey:query] objectForKey:@"kSecValueData"]` (0x009f5548 /
   0x009f555c) and decodes that blob as UTF-8 (`initWithData:encoding:4` at
   0x009f55ec), splitting on `"?"` (0x009f563c) — **exactly two parts** required
   (0x009f5658), with `[parts[1] longLongValue]` as the suffix (0x009f56b4).
3. **Ubiquitous store.** `[NSUbiquitousKeyValueStore defaultStore]` (0x009f5718)
   `stringForKey:@"iCloudIDv2"` (0x009f572c) with the `@"iCloudID"` fallback
   (0x009f57a0); a stored string without `"?"` yields suffix 100 (0x009f58a4).
4. **Keychain.** `[SFHFKeychainUtils getPasswordForUsername:@"com.majicjungle.blockheads.cloudid2"
   andServiceName:same error:&err]` (0x009f5928).

The smallest suffix wins (branch at 0x009f5a54); when no candidate exists the id is
generated as `MD5([[UIDevice currentDevice] uniqueDeviceIdentifier] + [NSString
stringByAppendingFormat:@"%lu%d", time(NULL) (0x009f5b40), lrand48() through the thunk
at 0x009f5e68 (0x009f5b48)])` (stringFromMD5 at 0x009f5b80), with the value taken from
`[NSDate timeIntervalSinceReferenceDate]` and converted by `__aeabi_d2lz`. Before the
bare id is returned (0x009f5d84) both stores are written: the ubiquitous store gets
`[NSString stringWithFormat:@"%@?%lld", id, suffix]` under `@"iCloudIDv2"`
(`setString:forKey:` at 0x009f5d2c) and the Keychain gets the same string through
`storeUsername:...updateExisting:1 error:` (0x009f5d74).

The helper at 0x009f5e68 is the same four-instruction thunk shape as the E9b batch's
0xd37798 (`push {fp,lr}; mov fp,sp; bl lrand48@plt; pop {fp,pc}`) — i.e. plain
`lrand48()`, used here as the entropy suffix of a freshly generated id. As in the rest
of this batch there is no VFP/float literal in the body: the only double is the runtime
`timeIntervalSinceReferenceDate` result.

## Anchors

| body | IMP | words | sel/imp/class | ivars | calls | branches |
|---|---|---:|---|---:|---:|---:|
| cm_instance | 0x009f3b14 | 50 | 2 / 1 / 1 | 0 | 2 | 1 |
| cm_init | 0x009f3bdc | 90 | 3 / 2 / 2 | 1 | 4 | 2 |
| cm_amount | 0x009f452c | 15 | 0 / 0 / 0 | 1 | 0 | 0 |
| cm_commitsaveifneeded | 0x009f4568 | 68 | 1 / 2 / 0 | 2 | 1 | 1 |
| cm_save | 0x009f4f34 | 16 | 0 / 0 / 0 | 1 | 0 | 0 |
| cm_modify_modifystring_ | 0x009f4f74 | 190 | 6 / 3 / 1 | 3 | 8 | 1 |
| cm_icloudid | 0x009f526c | 767 | 24 / 15 / 8 | 0 | 46 | 27 |
| cm_icloudserverrejoinid | 0x009f5e78 | 43 | 3 / 2 / 0 | 0 | 3 | 0 |
| cm_countwatcher | 0x009f5f24 | 17 | 0 / 0 / 0 | 1 | 0 | 0 |
| cm_setcountwatcher_ | 0x009f5f68 | 17 | 0 / 0 / 0 | 1 | 0 | 0 |
| cm_needssave | 0x009f5fac | 15 | 0 / 0 / 0 | 1 | 0 | 0 |
| cm_amountstring | 0x009f5fe8 | 17 | 0 / 0 / 0 | 1 | 0 | 0 |

Total: **12 bodies, 1305 verified words, 64 call sites, 32 branches, 12 ivar cells**,
every body with PIC base 0x0105faf4 recomputed from its own pool literal.

## Boundaries

- **Body ends are the listings' own ends, not the next ObjC IMP.** Three bodies are
  followed by non-method code, and the artifact records the distance instead of
  silently extending the body: `cm_commitsaveifneeded` ends 2236 bytes before
  `-save` (the gap is where its helpers live), `cm_amountstring` ends 364 bytes before
  the next class's method, and `cm_icloudid` ends 16 bytes early. `cm_countwatcher` is
  the opposite case (ARM.exidx over-covers into `-setCountWatcher:`) and its listing
  is trimmed at 0x009f5f68.
- **No floating point anywhere in this batch.** No `vmov`/`vldr`/`vstr` instruction
  appears in the 12 bodies, so none of the constant caveats from the E9b batch apply
  here.
- **The save body itself is not in this batch.** `commitSaveIfNeeded:` enqueues a
  block; the block body lives at 0x009f3f78 (its prologue is visible through the
  literal's pointer slot) and is plain C++/ARC code outside the ObjC method table, so
  it is out of scope for a method-level batch.
- **Load-relocated slots.** The block descriptor slot cell 0x009f4660 resolves to a
  slot whose file value is 0, and the singleton slot 0x01064984 is in BSS: both are
  load-time state, so the artifact reports the slot, not a value.
- **Strings are reported verbatim.** `7acfe93afc08c%d65ae2c54ecaf07f`,
  `7acfe93afc08%dc65ae2c54ecaf07f` and `rejoin` are the literal pool contents; what the
  fingerprints protect is a product decision, and no Keychain/crypto layer is claimed
  to be inside these bodies.
