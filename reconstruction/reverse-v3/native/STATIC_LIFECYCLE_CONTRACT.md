# Original 1.7.6 Android and Apportable lifecycle contract

This document separates original APK evidence from rebuild compatibility
choices. It does not require reproducing Apportable internals when a smaller
native lifecycle preserves the observed contract.

## Evidence levels

- **A**: directly present in original Manifest, decoded Java, ELF exports, or
  current rebuild source.
- **B**: reproduced by controlled runs of the original application.
- **C**: conclusion combining multiple A-level facts.
- **D**: implementation proposal.

This document contains A/C evidence only for the original.

## Launch and process model

[A] Original package/shared UID is `com.noodlecake.blockheads`. The application
class is `VerdeApplication`; the launcher is `VerdeActivity`.

[A] The original manifest declares one `singleTask` Activity for launch,
lifecycle, surface ownership, and incoming intents. Original runtime metadata
records minSdk 12, targetSdk 27, and version 1.7.6.

[A] Manifest metadata `android.app.libs` defines an ordered native library list
ending in `Application`. `LibraryManager.java:120-146` reads the list and loads
each library sequentially. `LibraryManager.java:203-218,472-540` initializes
`libv.so` after load and provides environment/path state including HOME,
cache/TMP, locale, timezone, and package metadata. HOME is internal
`filesDir` (`LibraryManager.java:520-525`).

[A] `libApplication.so` exports JNI entry points in these families:

- `Java_com_apportable_Lifecycle_*`
- `Java_com_apportable_VerdeActivity_nativeOn*`
- `nativeHandleUri`
- `Java_com_apportable_GLSurfaceView_nativeInit*`
- `Java_com_apportable_GLSurfaceView_nativeOnSurfaceChanged*`

## Startup gate

[A] `Lifecycle.java:269-278` gates native start on all of the following:
application initialized and created, Activity initialized and started,
libraries loaded, window focus, and a valid surface.

[A] `BackgroundLibraryLoader.java:24-44,47-138` loads libraries on Apportable's
runtime thread and queues/replays early create/start/resume/new-intent and
configuration actions.

[A] The surface is application-owned (`VerdeApplication.java:75-80`), detached
on stop, and reattached on start (`VerdeActivity.java:275-299,438-459`).

[C] Activity creation alone is not equivalent to engine readiness in the
original. Native execution is synchronized with focus, library readiness,
surface validity, and Activity state.

## EGL and context validity

[A] `GLSurfaceView.java:144-166` and `Lifecycle.java:219-247` track surface
create/change/destroy and explicit **context validity** state.

[A] `GLSurfaceView.java:443-513` creates or recreates EGL only when surface and
size are valid. `Lifecycle.java:250-267` distinguishes foreground/background
using focus, pause/stop, surface, and native-start state.

[A] Original native callbacks distinguish app active/background,
context-valid/context-invalid, low-memory, configuration, create, start,
resume, pause, stop, and destroy.

## Input contract

[A] `Window.java:152-200` forwards raw touches with phase, pointer ID,
coordinates, event time, separate pointer down/up, and complete pointer arrays
for move/cancel.

[A] `Window.java:203-225` forwards key down/up with key code, Alt state,
timestamp, and device ID.

[C] A tap/pan/scale-only bridge loses information needed for exact original
multi-touch and cancellation semantics.

## Orientation and external entry

[A] Original manifest and Apportable metadata declare portrait orientation.
The Activity is fullscreen/immersive, uses `adjustNothing`, and handles a broad
`configChanges` set.

[A] Initial and subsequent intents reach `nativeHandleUri`
(`VerdeActivity.java:199-239,729-755`). HTTP hosts include
`theblockheads.net` and `blockheads.noodlecake.com`; the custom scheme string is
literally `theblockheads.net/join`.

[A] Original APK native payload is ARMv7-only: 25 native libraries under
`armeabi-v7a`, with metadata `apportable.abi_list=armv7a`.

## Rebuild conformance ledger

Verified in current source/device acceptance:

- each `onSurfaceCreated` replaces renderer GL resources for that EGL context;
- chunk CPU mesh caches are requeued after context recreation;
- menu → game and HOME → game transitions no longer reuse stale GL names;
- device logs showed two renderer/context generations and terrain survived the
  second generation;
- current CI builds the exact pushed head on `reverse-v3`;
- current package intentionally uses `com.noodlecake.blockheads.rebuild`.

Outstanding evidence-backed gaps:

1. [A] The rebuild has separate landscape menu/game Activities rather than one
   portrait `singleTask` surface owner.
2. [A] It lacks an explicit native create/start/resume/pause/stop/destroy,
   focus, low-memory, configuration, surface-destroy, and context-invalid state
   machine.
3. [A] `initNative` executes from Activity setup rather than the complete
   original startup gate.
4. [A] Re-entering game still requires an audited process-idempotent engine and
   deterministic world/thread teardown.
5. [A] The input bridge does not preserve raw pointer IDs/phases/timestamps or
   full move/cancel arrays.
6. [A] Deep links, `onNewIntent`, and `nativeHandleUri` parity are absent.
7. [A] Runtime storage uses external app files and a custom `world.bin`; original
   HOME is internal files storage. Migration must be explicit.
8. [A] Build ABI policy includes modern ABIs; it is not an ARMv7-only package.

## Required acceptance scenarios

A lifecycle implementation is not accepted solely by compilation. Device
acceptance must preserve evidence for:

1. cold start;
2. menu surface creation followed by game surface creation;
3. nonzero rendered chunk/vertex state;
4. HOME/background then resume with a new EGL context;
5. terrain re-upload after context loss;
6. save, force-stop, relaunch, and same-world reload;
7. no fatal Java/native/GL errors in captured logs.

Runs through commit `983078f` have demonstrated items 1-6 for the rebuild's
current compatibility world format. They do not demonstrate original save
format compatibility or complete original lifecycle parity.
