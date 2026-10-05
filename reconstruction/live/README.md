# Live read-only instruments for the running original

These are the tools the live work was done with, moved into the repository so the next session has them. They
run on the device against the FOREGROUND original, read-only throughout: /proc/<pid>/maps for the layout and
pread on /proc/<pid>/mem for the bytes - no ptrace, no injection, no writes.

## The set

| tool | what it does |
|---|---|
| `probe_clock_175.py` | the `Probe` class everything else imports: ELF sections, live maps, the rw segment relocation used for class objects, `live_class`, `classlist_reloc`, `ivar_table`, `rdw`/`rds`, and `find_world` with its strong signature |
| `walk_from_world.py` | identify World by signature, then follow KNOWN ivar offsets, checking each hop's isa |
| `probe_craft_path.py` | follow the crafting path explicitly (World -> UIManager -> paintMixUI -> workbench) so a null hop is reported as null rather than as "nothing found" |
| `read_live_record.py` | read an instance's inline record for any class/ivar (e.g. CraftableItem @4, 124 bytes) |
| `rate_table_any.py` | sample any object's numeric ivars twice and print units/second - the semantic instrument |
| `sample_phase_flag.py` | sample the day phase, its direction flag, sun.y and worldTime at a chosen rate |
| `fit_phase.py` | fit the day phase against worldTime from a long sample (period + waveform + residual) |

## Discipline and gotchas that cost time

* **Check the build hash first.** The device runs 1.7.5 (sha `d09418e9...`) while the static baseline is 1.7.6
  (`733d8210...`). `probe_clock_175.py` REFUSES to measure a mismatched ELF; that refusal is the feature.
* **Under `su`, call the interpreter by absolute path** (`/data/data/com.termux/files/usr/bin/python3`):
  a root shell's PATH has no Termux, and `su -c python3 ...` says "inaccessible or not found".
* **Do the whole read inside one `su` invocation.** Each su costs tens of ms; scanning a 64 MB heap in 64 KB
  chunks through separate invocations takes tens of seconds.
* **Never identify instances by "first word == class pointer".** That matches class references held in tables and
  caches (18 false positives once). Identify a root by strong signature, then walk known ivar offsets and check
  each hop's isa.
* **Resolve a class object by relocating the ELF's `__objc_classlist` through the live rw segment** and
  cross-check it against the relocated classlist cell. Reading the `OBJC_CLASS_$_` symbol slot instead gave wrong
  answers.
* **Sampling rate is part of the evidence.** The day phase looked like a 2640-unit triangle wave from two samples
  60 s apart, and like a 900-unit sinusoid from 100 samples across three cycles. Two samples produced a wrong
  period AND a wrong correlation.
* **A BFS reporting "nothing found" and a path probe reporting "this hop is null" are different information.**
  Only the second tells the next person whether to wait for game state or go looking for another route.
* **Inline C++ containers stop an ObjC walk.** `DynamicWorld`'s `dynamicObjects` and friends are inline
  containers 780 bytes apart, so their contents are not reachable by following ivars.

## What has been verified live so far

* World found by signature; reachable: `World+416 DynamicWorld` (matching `world_layout.h`), `+240 UIManager`,
  `+420 WorldTileLoader`, and `World -> UIManager -> paintMixUI`.
* The modelled clock domain read at its own offsets: `sunDirection` is a UNIT vector, `fastForward == 1` while the
  clock advances 20.005 world units per wall second.
* Day phase measured: period ~900 world units (matching the static 900.0 constant), waveform a sinusoid
  (worst residual 0.04), direction flag = sign of its derivative.
* `DynamicWorld`: `worldChangedSimulateCounter` ~30/s, `dynamicObjectIDCount` +1 per 25 s.
* Not yet read: a live `CraftableItemObject` record - it needs a crafting screen open, since `PaintMixUI.workbench`
  and its neighbours are null in an idle world.
