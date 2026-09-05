# Reverse-engineering function coverage ledger

This generated ledger is conservative: indexed methods are not claimed to
have recovered semantics, replacement code, or behavioral verification.

- Source method map: `reconstruction/reverse-v3/native/libApplication_objc_methods.tsv`
- Methods: 10478
- Unique IMPs: 10478

| stage | count | meaning |
|---|---:|---|
| indexed | 10478 | present in the method map |
| refs | 24 | explicit implementation owner in refs/disassembly evidence |
| cfg | 21 | explicit IMP owner in CFG statistics or bounded disassembly; not a completeness claim |
| semantics | 0 | requires an explicit semantic audit; never inferred from names |
| implemented | 0 | requires an explicit replacement implementation record |
| behavior-verified | 0 | requires a controlled runtime behavior record |

Unknown/conditional/indirect cases remain unknown. This file is an index,
not a completion percentage or an equivalence claim.
