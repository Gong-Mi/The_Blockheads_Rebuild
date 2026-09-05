# Reverse v3

`reverse-v3` is the evidence-first reverse-engineering branch for The Blockheads 1.7.6.

`rebuild-v2` remains the speculative prototype and is not treated as an original-behavior baseline.

## Rules

1. Do not promote guessed algorithms, parameters, or entity mappings as original behavior.
2. Every recovered behavior gets an evidence record: source artifact, experiment, observation, and confidence.
3. Keep original APK behavior, native analysis, save-file analysis, and replacement implementation in separate directories.
4. A green Gradle build proves only that the replacement APK builds. It does not prove original behavior.
5. Device observations must record package version, APK hash, device build, timestamp, action sequence, logs, screenshots, and changed files.
6. Changes that implement a hypothesis must remain isolated from evidence collection and must be labelled as hypothesis-driven.

## Evidence levels

- A: directly observed in the original APK, native binary, or original save.
- B: reproduced by multiple controlled original-APK experiments.
- C: strongly correlated with symbols, strings, resource families, or one experiment.
- D: implementation hypothesis used only to make a prototype run.

Only A/B evidence may define an original-behavior contract. C evidence needs another experiment. D evidence must not be used as a compatibility claim.

## Work areas

```text
reconstruction/reverse-v3/
  apk/          exact APK metadata, hashes, manifests, asset paths
  native/       ELF, symbols, Objective-C metadata, disassembly indexes
  behavior/     action sequences and original-App observations
  saves/        original save snapshots and field-diff notes
  renderer/     GL/JNI/frame observations
  hypotheses/   explicitly unverified implementation hypotheses
```

## Milestones

### V3-0: preserve the evidence baseline

- Record the exact original APK hash and package metadata.
- Record the replacement APK hash separately.
- Record device build/GPU/ABI.
- Do not mix original and replacement app data directories.

### V3-1: original launch and state machine

Recover and record:

- launcher Activity;
- menu-to-world transition;
- surface creation/destruction order;
- JNI entry points;
- native initialization completion;
- return-to-menu and relaunch behavior.

### V3-2: original save format

Use controlled snapshots around one action at a time:

- first world creation;
- one block placement;
- one block break;
- inventory change;
- exit and relaunch.

No field is named or interpreted until its offset and change behavior are recorded.

### V3-3: renderer/chunk contract

Recover the observable contract before replacing it:

- surface dimensions;
- camera coordinates and scale;
- chunk request timing;
- mesh upload timing;
- shader/texture binding order;
- frame output after a known world state.

### V3-4: behavior slices

Implement only after the corresponding original observation exists:

- load one known world;
- render one known chunk;
- render player;
- select one inventory item;
- place/break one block;
- save/reload that state.

Multiplayer and broad simulation remain separate workstreams until their protocols and state models are evidenced.

## Acceptance reporting

Every report separates:

- construction: code and evidence tooling that exists;
- original behavior evidence: what was directly observed;
- replacement behavior: what the new APK actually does;
- unresolved hypotheses: what remains guessed;
- device acceptance: what was tested on a real device.
