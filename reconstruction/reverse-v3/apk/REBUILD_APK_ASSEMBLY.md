# Rebuild APK assembly (aapt2 / javac / d8 / zipalign / apksigner)

The flow that produced the device-verified 0.2-b5d and 0.2-b5e APKs on the
Termux/aarch64 host, with the two failure modes worth remembering.

## Steps

    T=$PREFIX/tmp/asm; mkdir -p $T/{gen,classes,dex-out,root/lib/arm64-v8a}
    AJ=$PREFIX/tmp/platform-36/android-36/android.jar

    # 1. resources
    aapt2 compile --dir app/src/main/res -o $T/res.zip

    # 2. link; NOTES on -A: use the REPO-ROOT assets/ (729 files, includes
    #    assets/gamedata/*). The app/src/main/assets tree does not carry
    #    gamedata and fails tools/validate_apk.py.
    aapt2 link -o $T/base.apk -I $AJ --manifest app/src/main/AndroidManifest.xml \
      -R $T/res.zip --java $T/gen --min-sdk-version 21 --target-sdk-version 34 \
      -A assets --auto-add-overlay

    # 3. java -> classes. NOTE: android.jar goes on -cp, NOT -bootclasspath:
    #    with -bootclasspath javac cannot resolve LambdaMetafactory and every
    #    lambda in the sources fails to compile.
    javac -source 8 -target 8 -cp $AJ -d $T/classes $(find app/src/main/java $T/gen -name '*.java')

    # 4. dex. NOTE: use d8, NOT dx.
    #    - dx --min-sdk-version<26 refuses lambdas (invokedynamic);
    #    - dx --min-sdk-version>=26 EMITS invokedynamic, which ART cannot run:
    #      the activity dies in onCreate with
    #        NoSuchMethodError: No static method metafactory(...)
    #        in class Ljava/lang/invoke/LambdaMetafactory;
    #    - the build-tools d8 shell wrappers assume Linux paths: call the jar.
    #    - ~/android-sdk/build-tools/36.0.0/d8 on this host is a no-op stub
    #      (`exit 0`); 34.0.0/35.0.0 have real d8.jar.
    mkdir -p $T/dex-out
    java -cp ~/android-sdk/build-tools/35.0.0/lib/d8.jar com.android.tools.r8.D8 \
      --min-api 21 --lib $AJ --output $T/dex-out $(find $T/classes -name '*.class')

    # 5. package dex + native libs (both .so came from build-apk-check / $PREFIX)
    cp $T/dex-out/classes.dex $T/root/classes.dex
    cp build-apk-check/libnative-lib.so $T/root/lib/arm64-v8a/
    cp $PREFIX/lib/libc++_shared.so   $T/root/lib/arm64-v8a/
    (cd $T/root && zip -X -q $T/base.apk classes.dex lib/arm64-v8a/*.so)

    # 6/7. align + sign with the app's device identity (CN=Debug; the in-tree
    #   app/debug.jks is a DIFFERENT identity -> upgrading an installed build
    #   would fail signature check)
    zipalign -f -p 4 $T/base.apk $T/aligned.apk
    apksigner sign --ks app/b5-debug.keystore --ks-pass pass:android \
      --ks-key-alias debug --key-pass pass:android \
      --out $T/rebuild.apk $T/aligned.apk

    # 8. checks
    apksigner verify --print-certs $T/rebuild.apk   # expect CN=Debug, sha256 da614209...
    aapt2 dump badging $T/rebuild.apk | head -1     # versionCode/versionName
    python3 tools/validate_apk.py $T/rebuild.apk    # apk-contract must PASS

## Device verification (host is the test device)

    P=$PREFIX/tmp/.../rebuild.apk
    su -c "pm install -r $P"
    su -c "input keyevent KEYCODE_WAKEUP"        # the launch is lost while asleep
    su -c 'am start-activity -W --user 0 -n com.noodlecake.blockheads.rebuild/.GameActivity'

    # outputs (external files dir):
    #   game_log.txt                     "Original snapshot loaded: blocks=.. records=.. objects=.. stub=.."
    #   original_snapshot_report.json    the full report

The all-types pass swaps the snapshot directory: back up
`files/original-snapshot`, copy a synthetic one in (one record per type;
`tools/test_client_snapshot_run.py`'s `build_snapshot()` generates exactly
that shape), relaunch, read the report, then restore and relaunch to leave
the device on its real snapshot.
