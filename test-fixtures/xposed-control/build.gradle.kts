plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "io.leemikepop.tamperprobe.lab.fixture.xposedcontrol"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.leemikepop.tamperprobe.lab.fixture.xposedcontrol"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            // The framework loads the hook class by the name in assets/xposed_init, so it must
            // never be renamed or stripped.
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

// AGP's built-in Kotlin support adds kotlin-stdlib to every module. This one is pure Java, and
// whatever the module APK contains is loaded into the process under test, so a positive control
// that should differ from its baseline only by one hook must not carry an unused library.
configurations.configureEach {
    exclude(group = "org.jetbrains.kotlin", module = "kotlin-stdlib")
}

dependencies {
    // Provided at runtime by the Xposed framework; bundling it would make the framework load a
    // second copy of its own API classes.
    compileOnly(libs.xposed.api)
}
