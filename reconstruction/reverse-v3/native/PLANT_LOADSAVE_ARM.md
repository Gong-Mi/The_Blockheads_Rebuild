# Plant loader — executed (level-B) ARM verification — batch b4b

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`

Second executed slice of the line, after b4a's NPC loader: the b3b decode of
`-[Plant loadSaveDictValues:]` (0x009554a0, **332 words**) now runs as original
instructions.

- `reconstruction/recovered/plant_load_save_dict.{h,cpp}` — recovered contract
  (`plant_gene_clamp`, `plant_load_save_dict_values`), CMake target
  `blockheads_recovered_plant` with `-fno-fast-math -ffp-contract=off`.
- `tools/test_plant_load_save_dict.cpp` — CTest contract
  (`recovered_plant_load_save_dict`), CI-visible without the ELF.
- `tools/plant_load_save_dict_arm_bridge.cpp` — -O0/-O2 bridge exporting the
  resulting field struct.
- `tools/test_plant_loadsave_arm.py` — executes the original method under
  Unicorn with a synthetic save dictionary.
- `tools/test_plant_loadsave_arm_evidence.py` — CI-safe guard (runs the
  differential when ELF+Unicorn exist, otherwise asserts the contract, the
  shared case table and the registrations).

Result (Termux, Unicorn 2.1.4):

```text
method  Plant -[loadSaveDictValues:]   entry 0x009554a0
cases   10
match   true — every planted field equal in the object's 100-byte instance
        for all cases, at the decoded widths:
        seasonOffset@68 word · age@72 float · gatherProgress@80 word ·
        frozen@76 / hasFloweredThisSeason@84 / flowering@85 byte ·
        maxAgeGene@54 / growthRateGene@56 halfword
```

What executed from the original binary: the whole 332-word body — every
`objectForKey:`/`intValue`/`floatValue`/`boolValue`/`doubleValue` call site,
all eight destructive stores at their decoded widths, the **real local clamp
helper at 0x004c0b70** (called twice per run, never re-implemented in the
harness) and the `worldTime - saveTime > 1800.0` gate. Only the message sends
are synthetic: `objectForKey:` on a fake dictionary, the four value
conversions on per-key boxed objects, and `worldTime` on a fake world object
reached through `self+4`.

Cases that pin the edges (all matched): gene sources `0`, `1`, `255`, `256`,
`300`, `32768`, `-1`, `-2`, `65535` (the halfword truncation happens *before*
the clamp, so `-1` becomes `65535` and clamps to `255`), and the gate at
`diff = 1800.5` (reset), `1800.0` exactly (no reset) and `1799.9999` (no
reset). The harness also asserts a small set of expectations independently of
the C++ pair, so a self-consistent-but-wrong pair cannot pass.

Boundaries (unchanged honesty rules): emulated original ARM with a synthetic
message graph — **not** Foundation, **not** the original-app runtime, **not**
device gameplay; the save dictionary, the boxed values and the world object are
stubs, and results stay outside the repository
(`~/blockheads-work/methods-save/scratch/plant-arm-differential/`). CI runs the
C++ contract test and the evidence guard only.
