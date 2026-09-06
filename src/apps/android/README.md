# LumiNet Android

This is the canonical Android application source root.

## Status

The uploaded archive contained Kotlin/Java fragments but no Gradle project, wrapper, manifest, or resources. This module supplies the missing project boundary and separates candidate production code from incomplete porting fragments.

## Toolchain

- Android Gradle Plugin 9.3.0
- Gradle 9.5.0
- JDK 17
- Kotlin 2.4.10 with built-in AGP Kotlin support
- compile/target SDK 37
- Compose BOM 2026.06.00

A Gradle wrapper is intentionally not fabricated. In a networked environment with Gradle 9.5.0 installed, run:

```bash
gradle wrapper --gradle-version 9.5.0
./gradlew :app:assembleDebug
```

The Android build was not executed in the audit environment because Gradle and Android SDK tooling were unavailable.

## Release signing

The repository does not contain or generate a production Android signing key. The release workflow builds and publishes `luminet-android-unsigned.apk`; sign that artifact with an externally provisioned release key before installation or distribution. This keeps key custody outside source control and avoids presenting an unsigned build as a production-ready APK.
