# CrystalManager `-[loadFromSave]` read-back evidence — batch b3e

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_crystalmanager_loadfromsave.py` →
`crystalmanager_loadfromsave.json`. Listing:
`disasm_crystalmanager_loadfromsave.txt` (506w).

```text
CrystalManager -[loadFromSave] 0x009f3d44 (506w) — no super call
  A. KEYCHAIN FIRST
     [SFHFKeychainUtils
        getPasswordForUsername:@"com.majicjungle.blockheads.crystalcount"
        andServiceName:@"com.majicjungle.blockheads.crystalcount"
        error:&err]                                    (call 0x009f3da4)
     if (password == nil)            → file path        (0x009f3db8 beq)
     if (err != nil)                 → file path        (0x009f3dc8 bne)
     else:
       crystalCount@8  = [password intValue]            (store 0x009f3e6c)
       amountString@12 = [[NSString stringWithFormat:
                            @"7acfe93afc08%dc65ae2c54ecaf07f",
                            crystalCount] stringFromMD5] retain
                                                        (store 0x009f3ed4)
       → return                                         (0x009f3ed8)

  B. FILE FALLBACK
     paths = NSSearchPathForDirectoriesInDomains(14,1,1)
             (ABI veneer 0x001c3f20 → slot 0x010602c4)
     p1    = [[paths objectAtIndex:0]
              stringByAppendingPathComponent:
              @"game/4bbf9ea9f3e11dd7afcb0f22ccb635d2"]
     s     = [NSString stringWithContentsOfFile:p1
                encoding:4 (NSUTF8StringEncoding) error:nil]
     if (s == nil) → return                             (0x009f3fc8 beq)
     data  = [NSData dataWithContentsOfFile:<game/%@ path>]  (0x009f42a4)
     data  = [data gzipInflate]                              (0x009f42bc)
     plist = thunk(data)  0x009f4508 → 0x009f602c             (0x009f42c0)
     if (plist == nil || derived == nil) → return             (0x009f42d4/e4)
     if (![derived isEqualToString:[plist objectForKey:@"loadSaveIDB"]])
         → return without writing                             (0x009f4350 beq)
     crystalCount@8  = [s intValue] >> 2   (asr r0,r0,#2 → store 0x009f4414)
     amountString@12 = [[NSString stringWithFormat:
                          @"7acfe93afc08%dc65ae2c54ecaf07f",
                          crystalCount] stringFromMD5] retain    (0x009f447c)
```

Facts:

- **The file stores 4× the crystal count**: the load does
  `[fileString intValue] >> 2` (`asr r0, r0, #2` at 0x009f4400) before writing
  `crystalCount@8`, while the keychain password feeds `intValue` 1:1 — so the
  two sources are not interchangeable byte-for-byte, they differ by a factor
  of four. Both paths then rebuild the same derived cache:
  `amountString@12 = retain(MD5(stringWithFormat:@"7acfe93afc08%dc65ae2c54ecaf07f",
  crystalCount))`.
- **The keychain guard rejects an error object as well as a nil password**:
  `password == nil` (0x9f3db8) *or* `err != nil` (0x9f3dc8) both divert to the
  file path; only a non-nil password with a nil error writes the ivars.
- **The file path has an anti-tamper gate**: after `gzipInflate` the payload
  is parsed by a local thunk (`0x009f4508 → 0x009f602c`; the callee is *not*
  decoded here), and the write only happens when the derived string
  `isEqualToString:` the parsed plist's `loadSaveIDB` entry. A mismatch
  returns without touching `crystalCount`/`amountString` — there is no partial
  write. The derived-string algebra (device name / `game/%@` / `%@_%@` /
  `stringFromMD5` mix) is gated call-site by call-site but deliberately left
  un-evaluated in this batch.
- **`__objc_classrefs` has two cell flavors in this binary**, both handled:
  zero file word + `R_ARM_ABS32` (`NSString`, `NSData` here) and a direct
  `R_ARM_RELATIVE` pointer to the class object (`SFHFKeychainUtils`,
  `UIDevice`). The keychain receiver is asserted to be
  `OBJC_CLASS_$_SFHFKeychainUtils`, and the ABI veneer 0x001c3f20 is asserted
  to resolve to the imported `NSSearchPathForDirectoriesInDomains`.
- **Negative controls 12/12**: the keychain class cell, the
  `NSSearchPath` directory constant (14), the UTF-8 encoding constant (4), a
  `bl` target relocation, the keychain guard branch, the `>> 2` shift, the
  `loadSaveIDB` branch, an ivar offset, two key-cell payloads and the two
  parser-thunk `bl` targets — each mutation must fail the run.
- Static level-A evidence only; the parsing thunk's callee, the derived-string
  algebra and the runtime roundtrip stay unresolved. Next natural boundaries:
  the 43 subclasses reading their own keys inside
  `initWithWorld:dynamicWorld:saveDict:cache:` overrides, plus the write-side
  counterpart `-[CrystalManager saveToFile]`/keychain writer (to pair this
  load against its storer).
