# Original client-world snapshot boundary

`OriginalClientWorld` is the next Method B boundary after offline record
assembly. It consumes `assemble_server_snapshot.py`'s `blocks/index.tsv` and
decoded raw physical-block files.

The index preserves the original database key as `key_hex`, while making the
proven coordinate explicit:

```text
key_hex    x    y    file             raw_sha256    bytes
305f30     0    0    blocks/0_0.raw   ...           65541
```

Each loaded block retains the original 1.7.6 layout:

```text
1024 × 64-byte OriginalTile
1-byte PhysicalBlock offset 13
4-byte little-endian PhysicalBlock offset 24
```

Acceptance contracts:

- ASCII `<signed-x>_<signed-y>` block keys are required;
- duplicate coordinates are rejected;
- raw files must be exactly 65,541 bytes;
- missing coordinates return `nullptr` without fabricating a block;
- a failed reload preserves the previous successfully loaded state;
- the original raw Tile structure is not cast onto the replacement packed `Tile`.

`assemble_server_snapshot.py` also emits `dynamic/index.tsv` and content-addressed
`dynamic/<sha256>.raw` files for every `dw` record. A leading `<x>_<y>/...` key
gets an explicit coordinate; keys without a proven coordinate remain indexed
with empty coordinate columns. The decoded plist is retained for inspection,
but no dynamic-object fields are guessed or materialized into entities yet.

This is a host-side snapshot container and a loader boundary. It is not yet the
replacement `GameWorld`, dynamic-object materialization, renderer input, save
back-write, original app execution, or Android device acceptance.
