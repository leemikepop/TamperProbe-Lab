plugins {
    id("com.android.application") version "9.2.1"
}

android {
    namespace = "io.leemikepop.tamperprobe.lab.raspfixture"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.leemikepop.tamperprobe.lab.raspfixture"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}
