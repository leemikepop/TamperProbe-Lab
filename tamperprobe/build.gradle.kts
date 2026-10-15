import java.util.Properties

val tamperProbeVersions = Properties().apply {
    file("version.properties").inputStream().use(::load)
}
val tamperProbeEngineVersion: String = tamperProbeVersions.getProperty("engineVersion")
val tamperProbeCatalogVersion: String = tamperProbeVersions.getProperty("catalogVersion")
val tamperProbeWireSchemaVersion: String = tamperProbeVersions.getProperty("wireSchemaVersion")

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "io.leemikepop.tamperprobe.lab.lib"
    compileSdk = 37
    ndkVersion = "27.0.12077973"

    defaultConfig {
        minSdk = 29

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
                arguments += listOf(
                    "-DTAMPERPROBE_ENGINE_VERSION=$tamperProbeEngineVersion",
                    "-DTAMPERPROBE_CATALOG_VERSION=$tamperProbeCatalogVersion",
                    "-DTAMPERPROBE_WIRE_SCHEMA_VERSION=$tamperProbeWireSchemaVersion",
                )
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        getByName("debug") {
            isJniDebuggable = rootProject.extra.get("debugJniDebuggable") as? Boolean ?: true
        }
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
    testOptions {
        unitTests.all {
            // TamperProbeE2ETestSuite only bundles the four e2e classes for running them together
            // from the IDE. Gradle already discovers those classes, so letting it run the suite
            // too executed every e2e test twice and reported 514 tests where 272 exist.
            it.exclude("**/TamperProbeE2ETestSuite*")
        }
    }
}

androidComponents {
    onVariants(selector().all()) { variant ->
        variant.sources.java?.addStaticSourceDirectory(
            rootProject.file("shared/drm-credential/src/main/java").absolutePath,
        )
        variant.sources.java?.addStaticSourceDirectory(
            rootProject.file("shared/fd-forensics/src/main/java").absolutePath,
        )
        variant.sources.java?.addStaticSourceDirectory(
            rootProject.file("shared/policy-oracle/src/main/java").absolutePath,
        )
        variant.sources.java?.addStaticSourceDirectory(
            rootProject.file("shared/tee-keystore/src/main/java").absolutePath,
        )
    }
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}

dependencies {
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.androidx.core.ktx)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

// ============================================
// Catalog generation
// ============================================

// The generator is plain Python 3 (standard library only). Set TAMPERPROBE_LAB_PYTHON to the
// interpreter to use; otherwise `python3` is used (`python` on Windows).
val pythonPath: String = System.getenv("TAMPERPROBE_LAB_PYTHON")
    ?: if (System.getProperty("os.name").lowercase().contains("windows")) "python" else "python3"

val generateDetectionsManifest = tasks.register<Exec>("generateDetectionsManifest") {
    description = "Validates the detector sidecars and generates the catalog manifest and package lists."
    group = "catalog"
    commandLine(pythonPath, file("scripts/generate_detections_manifest.py").absolutePath)
}

kotlin {
    explicitApi()
}

val generatedAssetsDir = layout.projectDirectory.dir("src/main/assets/tamperprobe")

val prepareTamperProbeAssets = tasks.register<Sync>("prepareTamperProbeAssets") {
    dependsOn(generateDetectionsManifest)
    into(generatedAssetsDir)
    from(file("scripts/generated/detections_manifest.json"))
    from(file("scripts/generated/package_indicators.txt"))
    from(file("scripts/generated/package_intent_actions.txt"))
    from(rootProject.file("shared/attestation/status.json")) {
        rename { "attestation_status.json" }
    }
    from(rootProject.file("shared/attestation/attestation_roots.json"))
}

tasks.configureEach {
    // Generate the catalog before anything compiles.
    if (name == "preBuild") {
        dependsOn(prepareTamperProbeAssets)
    }
}
