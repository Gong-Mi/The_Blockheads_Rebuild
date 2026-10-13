# DW record keys carry the type id (batch b5b, evidence)

The 2026-09-27 real-archive run of `client_app_skeleton_cli` over the
assembled `reverse-probe-001` snapshot produced:

```text
blocks 40, dynamic_records 10, dynamic_objects 0, unidentified_objects 16
```

because `original_client_app.cpp` looked for `objectType` /
`dynamicObjectType` keys inside each object dictionary — and the real
records do not contain them. This document pins where the type id
actually lives, from the original binary, before the loader changes.

## Evidence: the save key format embeds the type id

Direct string-table evidence from the pinned client ELF
(`lib/armeabi-v7a/libApplication.so`, sha256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`):

```text
readable_strings.txt:61841  %d_%d/chest_%llu        (chest cargo)
readable_strings.txt:61847  %@/%d                   (single-type record)
readable_strings.txt:61848  %@_%d_%d/%d              (save-side dw key)
readable_strings.txt:61856  %d_%d/%d                 (load-side dw key)
```

The load-side `%d_%d/%d` cluster (line 61856) sits with
`trying to load dynamic objects without physical block` (61855) and
`dupe object id` (61850) — i.e. inside the DynamicWorld load path. The
selector `saveDynamicObjectsForMacroTile:objectType:xPos:yPos:`
(methods TSV, `0x008b933c`) shows the save side groups records per
(objectType, x, y) into `%@_%d_%d/%d`; the load side strips the save-id
prefix, yielding `<macroX>_<macroY>/<objectType>`.

That matches every observed key in the real archive:
`3_16/1 3_16/13 4_16/28 4_16/4 4_16/45 4_16/7 5_16/11 5_16/12 5_16/59 5_16/62`,
each record's `dynamicObjects` array holding only the objects of that
one type (e.g. `5_16/59` → 4 TulipPlant dicts carrying `mateColorGenes`
/ `mixGenes`, `4_16/45` → the workbench dict with `workbenchType`).

## Scope and limits

- The type id is taken from the RECORD KEY, not from any object
  dictionary field; object dictionaries never claim a type in this
  format. `objectType`/`dynamicObjectType` stays as a FALLBACK for
  snapshot formats that carry it (the assembly metadata key), never
  as the primary source. The loader routing names this source
  `record_key` and a disagreement between the two sources is counted
  under `type_disagreement`, never silently resolved.
- The key suffix is the `classForDynamicObjectType` id domain
  (`dynamicobject_type_matrix.json`, 1..64) — the same table the
  registry consumes. `5_16/62` → TomatoPlant(62), `4_16/45` →
  Workbench(45).
- Multi-type keys other than `<x>_<y>/<type>` (e.g. `%@/%d`) are NOT
  covered here and remain refused (`out_of_range`/parse-failure
  counting), not guessed.
- This is static string+selector evidence for the key FORMAT. It does
  not yet execute the original load method; the executed differential
  for `DynamicWorld loadDynamicObjectsOfType:…` remains a separate
  acceptance layer.

## Post-fix verification (2026-09-27, batch b5b landed)

The rebuilt host CLI (`build-method/client_app_skeleton_cli`) re-ran over the
same assembled `reverse-probe-001` snapshot after the record-key routing
landed:

```text
blocks 40, dynamic_records 10, dynamic_objects 16, unidentified_objects 0
type_key_used: {"record_key": 16}    (no disagreements — the real object
                                      dictionaries carry no type key)
per_type: 1x2, 4x1, 7x1, 11x1, 12x2, 13x2, 28x1, 45x1, 59x4, 62x1
```

`5_16/59` → 4 objects (TulipPlant) and `4_16/45` → 1 object (Workbench)
resolve exactly as the key evidence predicts; before the fix the same run
reported `dynamic_objects 0` / `unidentified_objects 16`. The synthetic
fixture (`tools/make_client_app_fixture.py`, exercised by
`test_client_app_skeleton_evidence.py`) keeps the fallback and
unidentified/out-of-range/disagreement shapes covered without the archive.

Reproduce: assemble the snapshot with `tools/assemble_server_snapshot.py`
(world archive + `decode_original_block`), then run the CLI over the output
directory. This is host-level evidence over an assembled online-server
archive; it is not an original-runtime differential.
