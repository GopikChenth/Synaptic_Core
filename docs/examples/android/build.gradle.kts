// Merge into your Android app module's build.gradle.kts
android {
    compileSdk = 35 // SynapseSyncService overrides Service.onTimeout (API 35)

    defaultConfig {
        minSdk = 21
        ndk {
            // Must match the ABIs produced by scripts/build-android.sh
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    packaging {
        jniLibs {
            // REQUIRED for exec mode. Since AGP 3.6 native libs stay compressed inside
            // the APK and are never extracted, so nativeLibraryDir has no libsynapse.so
            // and ProcessBuilder fails with "error=2, No such file or directory".
            useLegacyPackaging = true
        }
    }

    // Unzip synapse-core-<version>-android-jniLibs.zip from the GitHub Release into
    // src/main/jniLibs/ (the default location), or point at a custom directory:
    // sourceSets["main"].jniLibs.srcDirs("third_party/synapse-core/jniLibs")
}
