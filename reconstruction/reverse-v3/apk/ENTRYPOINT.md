# Original Android entrypoint

Generated with `aapt2 dump badging` from the pinned original APK.

```text
package: com.noodlecake.blockheads
versionCode: 1564553369
versionName: 1.7.6
minSdkVersion: 12
targetSdkVersion: 27
native-code: armeabi-v7a
application label: The Blockheads
launchable Activity: com.apportable.activity.VerdeActivity
```

The replacement app's `com.noodlecake.blockheads.rebuild.MainMenuActivity` is
therefore not an equivalent Android entrypoint. It is a prototype shell. v3
must trace the `VerdeActivity`/Apportable startup path and the native lifecycle
before treating Activity behavior as recovered.
