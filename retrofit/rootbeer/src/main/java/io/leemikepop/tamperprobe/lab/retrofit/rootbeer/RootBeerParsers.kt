package io.leemikepop.tamperprobe.lab.retrofit.rootbeer

import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.retrofit.common.ProbeAnswer
import io.leemikepop.tamperprobe.lab.retrofit.common.ProbeResult
import io.leemikepop.tamperprobe.lab.retrofit.common.ShellOutput

/** Pure parsing for the shadow probes, kept apart from Android calls so it is JVM-testable. */
internal object RootBeerParsers {
    /** RootBeer's dangerous values, with the strength TamperProbe gives the same property. */
    val DANGEROUS_PROPS: Map<String, Pair<String, EvidenceStrength>> = linkedMapOf(
        "ro.debuggable" to ("1" to EvidenceStrength.WEAK),
        "ro.secure" to ("0" to EvidenceStrength.MODERATE),
    )

    /** Exists on every device and is readable by every app; anchors a getprop listing (Rule 2). */
    const val GETPROP_ANCHOR: String = "ro.build.version.sdk"

    private val getpropLine = Regex("""^\[(.+?)]: \[(.*)]$""")

    fun parseGetprop(lines: List<String>): Map<String, String> = lines.mapNotNull { line ->
        getpropLine.matchEntire(line.trim())?.destructured?.let { (key, value) -> key to value }
    }.toMap()

    /**
     * One probe per dangerous property. A property getprop did not list is not answered: on
     * current Android an app cannot read every property context, and getprop silently omits the
     * ones it cannot read.
     */
    fun dangerousPropProbes(output: ShellOutput): List<ProbeResult> {
        val noAnswer = output.noAnswerReason
        val properties = parseGetprop(output.lines)
        val anchorMissing = noAnswer == null && GETPROP_ANCHOR !in properties
        return DANGEROUS_PROPS.map { (key, dangerous) ->
            val value = properties[key]
            when {
                noAnswer != null -> ProbeResult(key, ProbeAnswer.NO_ANSWER, noAnswer)
                anchorMissing -> ProbeResult(key, ProbeAnswer.NO_ANSWER, "anchor_property_not_listed")
                value == null -> ProbeResult(key, ProbeAnswer.NO_ANSWER, "property_not_listed")
                value == dangerous.first -> ProbeResult(key, ProbeAnswer.PRESENT, value)
                else -> ProbeResult(key, ProbeAnswer.ABSENT, value)
            }
        }
    }

    data class MountEntry(val mountPoint: String, val options: List<String>)

    /**
     * Parses `mount` output as `RootBeer.checkForRWPaths()` does: split on single spaces; above
     * Android 6 the mount point is field 2 and the options field 5 in parentheses. Lines with
     * too few fields are skipped, as RootBeer skips them.
     */
    fun parseMounts(lines: List<String>, sdkInt: Int): List<MountEntry> = lines.mapNotNull { line ->
        val args = line.split(" ")
        val modern = sdkInt > ANDROID_M
        if ((!modern && args.size < 4) || (modern && args.size < 6)) return@mapNotNull null
        val mountPoint = if (modern) args[2] else args[1]
        var options = if (modern) args[5] else args[3]
        if (modern) options = options.replace("(", "").replace(")", "")
        MountEntry(mountPoint, options.split(","))
    }

    /**
     * One probe per path RootBeer checks. The mount table answers only if it was read and lists
     * the root mount point (Rule 2). A path that is not a mount point is answered "absent": the
     * question RootBeer asks is whether a mount at that path is rw.
     */
    fun rwPathProbes(output: ShellOutput, paths: List<String>, sdkInt: Int): List<ProbeResult> {
        val noAnswer = output.noAnswerReason
        val entries = parseMounts(output.lines, sdkInt)
        val anchorMissing = noAnswer == null && entries.none { it.mountPoint == "/" }
        return paths.map { path ->
            val matches = entries.filter { it.mountPoint.equals(path, ignoreCase = true) }
            when {
                noAnswer != null -> ProbeResult(path, ProbeAnswer.NO_ANSWER, noAnswer)
                anchorMissing -> ProbeResult(path, ProbeAnswer.NO_ANSWER, "anchor_root_mount_not_listed")
                matches.any { entry -> entry.options.any { it.equals("rw", ignoreCase = true) } } ->
                    ProbeResult(path, ProbeAnswer.PRESENT, "rw")
                matches.isEmpty() -> ProbeResult(path, ProbeAnswer.ABSENT, "not_a_mount_point")
                else -> ProbeResult(path, ProbeAnswer.ABSENT, "ro")
            }
        }
    }

    /**
     * `which <target>` answers only if `which sh` resolved through the same command (Rule 2).
     * A PRESENT probe carries the resolved path as its reason.
     */
    fun whichProbe(target: String, output: ShellOutput, anchor: ShellOutput): ProbeResult {
        val anchorReason = anchor.noAnswerReason ?: if (anchor.lines.isEmpty()) "anchor_sh_not_resolved" else null
        val noAnswer = output.noAnswerReason
        val resolved = output.lines.firstOrNull()
        return when {
            noAnswer != null -> ProbeResult(target, ProbeAnswer.NO_ANSWER, noAnswer)
            resolved != null -> ProbeResult(target, ProbeAnswer.PRESENT, resolved.trim())
            anchorReason != null -> ProbeResult(target, ProbeAnswer.NO_ANSWER, anchorReason)
            else -> ProbeResult(target, ProbeAnswer.ABSENT, "exit_${output.exitCode}")
        }
    }

    private const val ANDROID_M = 23
}
