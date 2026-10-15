plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "io.leemikepop.tamperprobe.lab.fixture.storageowner"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.leemikepop.tamperprobe.lab.fixture.storageowner"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}
