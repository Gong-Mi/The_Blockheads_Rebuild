# PLT veneer names (the .rel.plt → dynsym table)

Derived exactly as the harness does: `veneer = 0x1C27D4 + idx * 12` over
`.rel.plt` order, name from `.dynsym`. The names below are the ones the
front's listings reference; a name that surprises a write-up (memset where a
geometry helper was assumed) is the housekeeping code being resolved, not a
decode error.

| veneer | symbol |
|---|---|
| 0x1C281C | `objc_msgSend` |
| 0x1C2894 | `memcpy` |
| 0x1C2924 | `memset` |
| 0x1C2954 | `sin` |
| 0x1C29FC | `objc_msgSendSuper2` |
| 0x1C2B34 | `sinf` |
| 0x1C2B58 | `cosf` |
| 0x1C2E28 | `objc_enumerationMutation` |
| 0x1C2FE4 | `__wrap_calloc` |
| 0x1C3728 | `__aeabi_idiv` |
| 0x1C3F98 | `__wrap_powf` |

Notable consequences for the front's write-ups:

- the "geometry helper 0x1C2924/0x1C2E28" calls around the fast enumerations
  are `memset` + the enumeration mutation guard (compiler housekeeping);
- DPad's hit test (0x0070591C) calls `sinf`/`cosf` — it **rotates** the
  point before the four direction comparisons;
- GameUIView's render easing calls `__wrap_powf` (0x1C3F98) — a pow-based
  curve;
- the tree gene block's four divisions are `__aeabi_idiv` (0x1C3728) and the
  ArtificialLight tail's allocations are `__wrap_calloc` (0x1C2FE4).
