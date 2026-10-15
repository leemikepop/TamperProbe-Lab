package io.leemikepop.tamperprobe.lab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BuildVersionTest {
    @Test
    fun versionNameUsesMajorMinorAndCommitCount() {
        assertEquals(
            "${BuildConfig.VERSION_MAJOR}.${BuildConfig.VERSION_MINOR}.${BuildConfig.GIT_COMMIT_COUNT}",
            BuildConfig.VERSION_NAME,
        )
        assertEquals(BuildConfig.GIT_COMMIT_COUNT, BuildConfig.VERSION_CODE)
    }

    @Test
    fun commitMetadataHasExpectedShape() {
        assertTrue(BuildConfig.GIT_COMMIT.matches(Regex("[0-9a-f]{12}")))
        assertTrue(BuildConfig.GIT_COMMIT_COUNT > 0)
    }
}
