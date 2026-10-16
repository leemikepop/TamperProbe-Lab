package io.leemikepop.tamperprobe.lab.retrofit.ruru

import io.leemikepop.tamperprobe.lab.retrofit.common.ProbeAnswer
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Test

class RuruShadowTest {
    private val names = mapOf(1 to "EPERM", 2 to "ENOENT", 13 to "EACCES", 20 to "ENOTDIR")
    private val errnoName: (Int) -> String = { names[it] ?: "errno_$it" }
    private val notAttempted = RuruShadow.NOT_ATTEMPTED

    @Test
    fun libcIsAbsentOnlyWhenEveryCallSaysTheFileIsNotThere() {
        val absent = RuruShadow.classifyLibc("/p", intArrayOf(2, 2, 2, notAttempted), errnoName)
        assertEquals(ProbeAnswer.ABSENT, absent.answer)

        // Upstream maps this to NOT_FOUND; the path was never answered.
        val denied = RuruShadow.classifyLibc("/p", intArrayOf(13, 13, 13, notAttempted), errnoName)
        assertEquals(ProbeAnswer.NO_ANSWER, denied.answer)
        assertEquals("EACCES", denied.reason)

        val mixed = RuruShadow.classifyLibc("/p", intArrayOf(2, 13, 2, notAttempted), errnoName)
        assertEquals(ProbeAnswer.NO_ANSWER, mixed.answer)
    }

    @Test
    fun anySuccessfulLibcCallIsPresent() {
        val present = RuruShadow.classifyLibc("/p", intArrayOf(13, 13, 0, 0), errnoName)
        assertEquals(ProbeAnswer.PRESENT, present.answer)
    }

    @Test
    fun syscallFollowsUpstreamSemantics() {
        assertEquals(ProbeAnswer.PRESENT, RuruShadow.classifySyscall("/p", 0, errnoName).answer)
        assertEquals(ProbeAnswer.PRESENT, RuruShadow.classifySyscall("/p", 1, errnoName).answer)
        assertEquals(ProbeAnswer.ABSENT, RuruShadow.classifySyscall("/p", 20, errnoName).answer)
        assertEquals(ProbeAnswer.NO_ANSWER, RuruShadow.classifySyscall("/p", 13, errnoName).answer)
        val sigsys = RuruShadow.classifySyscall("/p", RuruShadow.SIGSYS_MARKER, errnoName)
        assertEquals(RuruShadow.SIGSYS, sigsys.reason)
    }

    @Test
    fun pmListIsReadAsPmCommandReadsIt() {
        val parsed = RuruParsers.parsePmList(listOf("package:android", "  PACKAGE:com.example ", "package:", "junk"))
        assertEquals(setOf("android", "com.example"), parsed)
    }

    @Test
    fun shadowTargetsMatchTheVendoredAbnormalEnvironment() {
        val source = File("upstream/java/icu/nullptr/applistdetector/AbnormalEnvironment.kt").readText()
        val places = Regex("""val places = arrayOf\((.*?)\)""").find(source)!!.groupValues[1]
            .split(",").map { it.trim().removeSurrounding("\"") }
        assertEquals(RuruConstants.ROOT_BINARY_PLACES, places)

        val detected = Regex("""detectFile\("([^"]+)"\)""").findAll(source).map { it.groupValues[1] }.toSet()
        assertEquals(detected, RuruConstants.MARKER_FILES.values.flatten().toSet())

        RuruConstants.MARKER_FILES.keys.forEach { assertEquals(true, source.contains("\"$it\"")) }
        RuruConstants.ROOT_BINARY_ITEMS.keys.forEach { assertEquals(true, source.contains("\"$it\"")) }
    }

    @Test
    fun shadowFamiliesMatchTheVendoredFileDetection() {
        val source = File("upstream/java/icu/nullptr/applistdetector/FileDetection.kt").readText()
        val families = Regex("""detect\("([^"]+)\${'$'}packageName", useSyscall\)""").findAll(source)
            .map { it.groupValues[1] + "%s" }.toList()
        assertEquals(RuruConstants.DATA_PATH_FAMILIES, families)
    }
}
