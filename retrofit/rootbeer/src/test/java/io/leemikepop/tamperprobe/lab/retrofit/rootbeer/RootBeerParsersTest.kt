package io.leemikepop.tamperprobe.lab.retrofit.rootbeer

import io.leemikepop.tamperprobe.lab.retrofit.common.ProbeAnswer
import io.leemikepop.tamperprobe.lab.retrofit.common.ShellOutput
import org.junit.Assert.assertEquals
import org.junit.Test

class RootBeerParsersTest {
    private fun ran(stdout: String, exit: Int = 0) = ShellOutput(true, exit, stdout, "", null)

    private val notStarted = ShellOutput(false, null, "", "", "IOException")

    @Test
    fun dangerousPropertiesAreAnsweredOnlyWhenListedNextToTheAnchor() {
        val probes = RootBeerParsers.dangerousPropProbes(
            ran("[ro.build.version.sdk]: [37]\n[ro.debuggable]: [0]\n"),
        ).associateBy { it.target }

        assertEquals(ProbeAnswer.ABSENT, probes.getValue("ro.debuggable").answer)
        assertEquals(ProbeAnswer.NO_ANSWER, probes.getValue("ro.secure").answer)
        assertEquals("property_not_listed", probes.getValue("ro.secure").reason)
    }

    @Test
    fun dangerousValuesArePresent() {
        val probes = RootBeerParsers.dangerousPropProbes(
            ran("[ro.build.version.sdk]: [33]\n[ro.debuggable]: [1]\n[ro.secure]: [0]\n"),
        )
        assertEquals(listOf(ProbeAnswer.PRESENT, ProbeAnswer.PRESENT), probes.map { it.answer })
    }

    @Test
    fun aListingWithoutTheAnchorAnswersNothing() {
        val probes = RootBeerParsers.dangerousPropProbes(ran("[ro.debuggable]: [0]\n[ro.secure]: [1]\n"))
        assertEquals(setOf("anchor_property_not_listed"), probes.map { it.reason }.toSet())
        assertEquals(setOf(ProbeAnswer.NO_ANSWER), probes.map { it.answer }.toSet())
    }

    @Test
    fun getpropThatDidNotStartAnswersNothing() {
        val probes = RootBeerParsers.dangerousPropProbes(notStarted)
        assertEquals(setOf("exec_failed_IOException"), probes.map { it.reason }.toSet())
    }

    @Test
    fun mountsAreParsedAsRootBeerParsesThem() {
        val output = ran(
            "/dev/block/dm-0 on / type ext4 (ro,seclabel,relatime)\n" +
                "/dev/block/dm-7 on /vendor/bin type ext4 (rw,seclabel)\n" +
                "tmpfs on /sbin type tmpfs (ro)\n" +
                "short line\n",
        )
        val probes = RootBeerParsers.rwPathProbes(output, listOf("/system", "/vendor/bin", "/sbin"), sdkInt = 37)
            .associateBy { it.target }

        assertEquals(ProbeAnswer.ABSENT, probes.getValue("/system").answer)
        assertEquals("not_a_mount_point", probes.getValue("/system").reason)
        assertEquals(ProbeAnswer.PRESENT, probes.getValue("/vendor/bin").answer)
        assertEquals("ro", probes.getValue("/sbin").reason)
    }

    @Test
    fun aMountTableWithoutTheRootMountAnswersNothing() {
        val probes = RootBeerParsers.rwPathProbes(ran("tmpfs on /dev type tmpfs (rw)\n"), listOf("/system"), 37)
        assertEquals(ProbeAnswer.NO_ANSWER, probes.single().answer)
        assertEquals("anchor_root_mount_not_listed", probes.single().reason)
    }

    @Test
    fun whichAnswersOnlyWhenShResolves() {
        val absent = RootBeerParsers.whichProbe("su", ran("", exit = 1), ran("/system/bin/sh\n"))
        assertEquals(ProbeAnswer.ABSENT, absent.answer)

        val unanchored = RootBeerParsers.whichProbe("su", ran("", exit = 1), ran("", exit = 1))
        assertEquals(ProbeAnswer.NO_ANSWER, unanchored.answer)
        assertEquals("anchor_sh_not_resolved", unanchored.reason)

        val present = RootBeerParsers.whichProbe("su", ran("/system/bin/su\n"), ran("/system/bin/sh\n"))
        assertEquals(ProbeAnswer.PRESENT, present.answer)
        assertEquals("/system/bin/su", present.reason)
    }
}
