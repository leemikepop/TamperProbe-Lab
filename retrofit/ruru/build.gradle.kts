plugins {
    alias(libs.plugins.android.application)
}

fun gitOutput(vararg arguments: String): String = runCatching {
    providers.exec {
        commandLine("git", *arguments)
        workingDir(rootProject.projectDir)
        isIgnoreExitValue = true
    }.standardOutput.asText.get().trim()
}.getOrDefault("")

val gitCommitCount = gitOutput("rev-list", "--count", "HEAD").toIntOrNull() ?: 1
val gitCommit = gitOutput("rev-parse", "--short=12", "HEAD").ifEmpty { "000000000000" }
val gitDirty = gitOutput("--no-optional-locks", "status", "--porcelain").isNotEmpty()

android {
    namespace = "io.leemikepop.tamperprobe.lab.retrofit.ruru"
    compileSdk = 37
    ndkVersion = "27.0.12077973"

    defaultConfig {
        applicationId = "io.leemikepop.tamperprobe.lab.retrofit.ruru"
        minSdk = 29
        // As Ruru ships (build.gradle.kts: targetSdkVer 29): no package-visibility filtering and
        // legacy external storage. A higher target would change what its checks can see.
        targetSdk = 29
        versionCode = gitCommitCount
        versionName = "1.0.$gitCommitCount"

        buildConfigField("String", "GIT_COMMIT", "\"$gitCommit\"")
        buildConfigField("boolean", "GIT_DIRTY", gitDirty.toString())

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters.addAll(setOf("x86", "x86_64", "armeabi-v7a", "arm64-v8a"))
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    buildFeatures {
        buildConfig = true
        prefab = true
    }

    lint {
        // The old target is the point: it reproduces Ruru's release configuration.
        disable += setOf("ExpiredTargetSdkVersion", "OldTargetApi")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

androidComponents {
    onVariants(selector().all()) { variant ->
        // Ruru's library sources at 30694c2, unchanged (see upstream/UPSTREAM.md).
        variant.sources.kotlin?.addStaticSourceDirectory(file("upstream/java").absolutePath)
        // assets/stub.apk from the Ruru 1.1.1 release, which MagiskApp compares against.
        variant.sources.assets?.addStaticSourceDirectory(file("upstream/assets").absolutePath)
    }
}

kotlin {
    jvmToolchain(11)
    compilerOptions {
        // Ruru compiles against SDK 33, where PackageInfo's fields carry no nullability. SDK 37
        // annotates them @android.annotation.Nullable, which turns upstream's unchanged code into
        // errors. As warnings, the fields are platform types again, as when upstream compiled.
        freeCompilerArgs.add("-Xnullability-annotations=@android.annotation:warn")
    }
}

dependencies {
    implementation(project(":retrofit:common"))
    implementation(libs.xposed.detector)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
