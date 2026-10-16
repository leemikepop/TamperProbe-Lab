plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "io.leemikepop.tamperprobe.lab.retrofit.common"
    compileSdk = 37

    defaultConfig {
        minSdk = 29
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

androidComponents {
    onVariants(selector().all()) { variant ->
        // The same Evidence Contract model the SDK compiles, so the retrofits are held to the
        // same invariants (DetectorResult and EvidenceUnitResult check them on construction).
        variant.sources.kotlin?.addStaticSourceDirectory(
            rootProject.file("shared/evidence-contract/src/main/java").absolutePath,
        )
    }
}

kotlin {
    jvmToolchain(11)
}

dependencies {
    api(libs.kotlinx.serialization.json)
    testImplementation(libs.junit)
}
