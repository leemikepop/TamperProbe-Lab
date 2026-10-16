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
    namespace = "io.leemikepop.tamperprobe.lab.retrofit.rootbeer"
    compileSdk = 37
    ndkVersion = "27.0.12077973"

    defaultConfig {
        applicationId = "io.leemikepop.tamperprobe.lab.retrofit.rootbeer"
        minSdk = 29
        // A current target, as an app integrating RootBeer today must have: package visibility
        // filtering applies, and the manifest declares RootBeer's packages under <queries>.
        targetSdk = 36
        versionCode = gitCommitCount
        versionName = "1.0.$gitCommitCount"

        buildConfigField("String", "GIT_COMMIT", "\"$gitCommit\"")
        buildConfigField("boolean", "GIT_DIRTY", gitDirty.toString())

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // As rootbeerlib/build.gradle.kts at de7bc7b builds libtoolChecker.so.
        ndk {
            abiFilters.addAll(setOf("x86", "x86_64", "armeabi-v7a", "arm64-v8a"))
        }
        externalNativeBuild {
            cmake {
                arguments.add("-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON")
                cFlags("-fPIC")
                cppFlags("-fPIC")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Installs over a debug build in place: an uninstall would detach the concealment
            // configuration the test devices hold against this package.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    // RootBeer's own CMake file, unchanged.
    externalNativeBuild {
        cmake {
            path = file("upstream/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

androidComponents {
    onVariants(selector().all()) { variant ->
        // RootBeer's Java sources at de7bc7b, unchanged (see upstream/UPSTREAM.md).
        variant.sources.java?.addStaticSourceDirectory(file("upstream/java").absolutePath)
    }
}

kotlin {
    jvmToolchain(11)
}

dependencies {
    implementation(project(":retrofit:common"))
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    // Brings androidx.test:runner (AndroidJUnitRunner), as for :app.
    androidTestImplementation(libs.androidx.espresso.core)
}
