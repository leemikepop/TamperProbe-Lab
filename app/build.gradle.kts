import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

val appVersions = Properties().apply {
    file("version.properties").inputStream().use(::load)
}
val tamperProbeVersions = Properties().apply {
    rootProject.file("tamperprobe/version.properties").inputStream().use(::load)
}

fun gitOutput(vararg arguments: String): String = runCatching {
    providers.exec {
        commandLine("git", *arguments)
        workingDir(rootProject.projectDir)
        isIgnoreExitValue = true
    }.standardOutput.asText.get().trim()
}.getOrDefault("")

val versionMajor = appVersions.getProperty("versionMajor").toInt()
val versionMinor = appVersions.getProperty("versionMinor").toInt()
val gitCommitCount = gitOutput("rev-list", "--count", "HEAD").toIntOrNull() ?: 1
val gitCommit = gitOutput("rev-parse", "--short=12", "HEAD").ifEmpty { "000000000000" }
val gitDirty = gitOutput("--no-optional-locks", "status", "--porcelain").isNotEmpty()
val appVersionName = "$versionMajor.$versionMinor.$gitCommitCount"

android {
    namespace = "io.leemikepop.tamperprobe.lab"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.leemikepop.tamperprobe.lab"
        minSdk = 29
        targetSdk = 36
        versionCode = gitCommitCount
        versionName = appVersionName

        buildConfigField("int", "VERSION_MAJOR", versionMajor.toString())
        buildConfigField("int", "VERSION_MINOR", versionMinor.toString())
        buildConfigField("int", "GIT_COMMIT_COUNT", gitCommitCount.toString())
        buildConfigField("String", "GIT_COMMIT", "\"$gitCommit\"")
        buildConfigField("boolean", "GIT_DIRTY", gitDirty.toString())
        buildConfigField(
            "String",
            "TAMPERPROBE_ENGINE_VERSION",
            "\"${tamperProbeVersions.getProperty("engineVersion")}\"",
        )
        buildConfigField(
            "String",
            "TAMPERPROBE_CATALOG_VERSION",
            "\"${tamperProbeVersions.getProperty("catalogVersion")}\"",
        )
        buildConfigField(
            "int",
            "TAMPERPROBE_CATALOG_SCHEMA_VERSION",
            tamperProbeVersions.getProperty("catalogSchemaVersion"),
        )
        buildConfigField(
            "int",
            "TAMPERPROBE_EVIDENCE_CONTRACT_VERSION",
            tamperProbeVersions.getProperty("evidenceContractVersion"),
        )
        buildConfigField(
            "int",
            "TAMPERPROBE_WIRE_SCHEMA_VERSION",
            tamperProbeVersions.getProperty("wireSchemaVersion"),
        )

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Measuring release-build cost needs instrumented tests against the release variant,
    // whose native engine is compiled with optimisation. Opt in per invocation with
    // -Ptamperprobe.instrumentRelease=true. The release APK is then signed with the debug
    // key, so it installs over an existing debug build in place: an uninstall would detach
    // the concealment configuration the test devices hold against this package.
    val instrumentRelease = providers.gradleProperty("tamperprobe.instrumentRelease")
        .map { it.toBoolean() }
        .getOrElse(false)
    if (instrumentRelease) {
        testBuildType = "release"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (instrumentRelease) {
                signingConfig = signingConfigs.getByName("debug")
            }
        }
        getByName("debug") {
            // 啟用 JNI 除錯 (允許 native 層斷點)
            isJniDebuggable = rootProject.extra["debugJniDebuggable"] as Boolean
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        buildConfig = true
        compose = true
        viewBinding = true
    }
}

val verifyCleanReleaseTree = tasks.register("verifyCleanReleaseTree") {
    group = "verification"
    description = "Fails release packaging when the Git working tree is dirty."
    inputs.property("gitDirty", gitDirty)
    doLast {
        check(!gitDirty) {
            "Release packaging requires a clean Git working tree so the artifact maps to an exact commit."
        }
    }
}

tasks.configureEach {
    // IDE import may compile release sources; guard only artifact-producing tasks.
    if (name == "packageRelease" || name == "packageReleaseBundle") {
        dependsOn(verifyCleanReleaseTree)
    }
}

kotlin {
    jvmToolchain(11)
}

dependencies {
    implementation(project(":tamperprobe"))
    // TamperProbe Library

    // AndroidX Core
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)

    // Jetpack Compose
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.core)
    implementation(libs.androidx.activity.compose)

    // Lifecycle
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.kotlinx.serialization.json)

    // Debugging Tools
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)

    // Testing
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
}
