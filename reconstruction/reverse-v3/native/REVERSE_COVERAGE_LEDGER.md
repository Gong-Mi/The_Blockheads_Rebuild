# Reverse-engineering function coverage ledger

This generated ledger is conservative: indexed methods are not claimed to
have recovered semantics, replacement code, or behavioral verification.

- Source method map: `reconstruction/reverse-v3/native/libApplication_objc_methods.tsv`
- Methods: 10478
- Unique IMPs: 10478

| stage | count | meaning |
|---|---:|---|
| indexed | 10478 | present in the method map |
| refs | 58 | explicit implementation owner in refs/disassembly evidence |
| cfg | 57 | explicit IMP owner in CFG statistics or bounded disassembly; not a completeness claim |
| semantics | 35 | explicit reviewed method records and their stated limits |
| implemented | 35 | explicit source/test/evidence records; not gameplay integration |
| behavior-verified | 0 | controlled original-runtime evidence, not local fixtures |

Unknown/conditional/indirect cases remain unknown. This file is an index,
not a completion percentage or an equivalence claim.
