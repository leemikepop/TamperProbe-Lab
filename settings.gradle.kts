pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Only the legacy Xposed API artifact, compile-only, for the xposed-control research
        // fixture. The content filter keeps every other dependency off this repository.
        maven("https://api.xposed.info/") {
            content { includeGroup("de.robv.android.xposed") }
        }
    }
}

rootProject.name = "TamperProbe-Lab"
include(":app")
include(":tamperprobe")
include(":tamperprobe-rasp")
include(":test-fixtures:storage-owner")
include(":test-fixtures:xposed-control")
