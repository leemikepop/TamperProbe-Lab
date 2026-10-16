package io.leemikepop.tamperprobe.lab.retrofit.rootbeer

import android.content.Context
import android.os.Build
import com.scottyab.rootbeer.RootBeer
import com.scottyab.rootbeer.UpstreamConstants
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.retrofit.common.CheckEvaluation
import io.leemikepop.tamperprobe.lab.retrofit.common.CheckSpec
import io.leemikepop.tamperprobe.lab.retrofit.common.Finding
import io.leemikepop.tamperprobe.lab.retrofit.common.PackageProbe
import io.leemikepop.tamperprobe.lab.retrofit.common.PackageVisibilityScope
import io.leemikepop.tamperprobe.lab.retrofit.common.PathProbe
import io.leemikepop.tamperprobe.lab.retrofit.common.ProbeAnswer
import io.leemikepop.tamperprobe.lab.retrofit.common.ProbeResult
import io.leemikepop.tamperprobe.lab.retrofit.common.ShellOutput
import io.leemikepop.tamperprobe.lab.retrofit.common.UnitEvaluation
import io.leemikepop.tamperprobe.lab.retrofit.common.UpstreamIdentity
import io.leemikepop.tamperprobe.lab.retrofit.common.evaluateCheck
import java.io.File

/**
 * Reports RootBeer's checks through the Evidence Contract.
 *
 * Each check is the unmodified upstream method; its boolean is the upstream verdict and decides
 * every positive. A shadow probe then repeats the check's call on the same channel to learn what
 * RootBeer discards: which targets the channel actually answered for. RootBeer returns `false`
 * both when a channel answered "absent" and when it could not answer; the retrofit separates them.
 */
class RootBeerRetrofit(private val context: Context) {
    private val rootBeer = RootBeer(context)

    private val packageScope: PackageVisibilityScope = PackageVisibilityScope.resolve(context, declaredPackages())

    val packageVisibility: String
        get() = when (val scope = packageScope) {
            is PackageVisibilityScope.All -> scope.basis
            is PackageVisibilityScope.Declared -> "${scope.basis}:${scope.packages.size}"
        }

    /** Runs every check of `isRooted()`, each to completion (upstream short-circuits; we do not). */
    fun evaluate(): List<CheckEvaluation> = listOf(
        packageCheck(RootBeerSpecs.ROOT_MANAGEMENT_APPS, UpstreamConstants.rootManagementPackages) {
            rootBeer.detectRootManagementApps()
        },
        packageCheck(RootBeerSpecs.DANGEROUS_APPS, UpstreamConstants.dangerousPackages) {
            rootBeer.detectPotentiallyDangerousApps()
        },
        binaryCheck(RootBeerSpecs.SU_BINARY, UpstreamConstants.BINARY_SU) {
            rootBeer.checkForBinary(UpstreamConstants.BINARY_SU)
        },
        dangerousPropsCheck(),
        rwPathsCheck(),
        testKeysCheck(),
        whichSuCheck(),
        nativeSuCheck(),
        binaryCheck(RootBeerSpecs.MAGISK_BINARY, "magisk") { rootBeer.checkForMagiskBinary() },
    )

    /** `isRooted()` exactly as an integrator calls it. */
    fun aggregateVerdict(): String = runCatching { rootBeer.isRooted().toString() }
        .getOrElse { "threw:${it.javaClass.name}" }

    private fun packageCheck(
        spec: CheckSpec,
        packages: List<String>,
        upstream: () -> Boolean,
    ): CheckEvaluation = evaluateCheck(spec, upstream) { positive ->
        val call = PackageProbe.packageInfoLookup(context)
        val anchor = PackageProbe.anchor(context, call)
        val probes = PackageProbe.qualify(packages.map { PackageProbe.lookup(it, call) }, packageScope, anchor)
        val findings = probes.filter { it.answer == ProbeAnswer.PRESENT }.map {
            Finding(
                code = "installed-package",
                summary = "A package on RootBeer's list is installed",
                strength = EvidenceStrength.WEAK,
                attributes = mapOf("packageName" to it.target),
            )
        }
        listOf(UnitEvaluation(spec.units.single().id, positive.toString(), positive, probes, findings))
    }

    private fun binaryCheck(spec: CheckSpec, binary: String, upstream: () -> Boolean): CheckEvaluation =
        evaluateCheck(spec, upstream) { positive ->
            val directories = UpstreamConstants.binaryDirectories()
            val anchor = PathProbe.stat(PathProbe.ANCHOR_PATH)
            // File(directory, name), as RootBeer builds the path.
            val probes = PathProbe.anchored(anchor, directories.map { PathProbe.stat(File(it, binary).path) })
            val findings = binaryFindings(directories, probes) { File(it, binary).path }
            listOf(UnitEvaluation(spec.units.single().id, positive.toString(), positive, probes, findings))
        }

    private fun nativeSuCheck(): CheckEvaluation {
        val spec = RootBeerSpecs.NATIVE_SU
        return evaluateCheck(spec, { rootBeer.checkForRootNative() }) { positive ->
            val directories = UpstreamConstants.binaryDirectories()
            // paths[i] + BINARY_SU, as checkForRootNative() builds the path.
            val paths = directories.map { it + UpstreamConstants.BINARY_SU }
            val probes = if (!UpstreamConstants.nativeLibraryLoaded()) {
                paths.map { ProbeResult(it, ProbeAnswer.NO_ANSWER, "native_library_not_loaded") }
            } else {
                PathProbe.anchored(PathProbe.openReadOnly(PathProbe.ANCHOR_PATH), paths.map(PathProbe::openReadOnly))
            }
            val findings = binaryFindings(directories, probes) { it + UpstreamConstants.BINARY_SU }
            listOf(UnitEvaluation(spec.units.single().id, positive.toString(), positive, probes, findings))
        }
    }

    private fun dangerousPropsCheck(): CheckEvaluation {
        val spec = RootBeerSpecs.DANGEROUS_PROPS
        return evaluateCheck(spec, { rootBeer.checkForDangerousProps() }) { positive ->
            val output = ShellOutput.run("getprop")
            val probes = RootBeerParsers.dangerousPropProbes(output)
            val properties = RootBeerParsers.parseGetprop(output.lines)
            val findings = probes.filter { it.answer == ProbeAnswer.PRESENT }.map {
                Finding(
                    code = "dangerous-property",
                    summary = "A property RootBeer checks has its dangerous value",
                    strength = RootBeerParsers.DANGEROUS_PROPS.getValue(it.target).second,
                    attributes = mapOf("property" to it.target, "value" to properties[it.target].orEmpty()),
                )
            }
            listOf(UnitEvaluation(spec.units.single().id, positive.toString(), positive, probes, findings))
        }
    }

    private fun rwPathsCheck(): CheckEvaluation {
        val spec = RootBeerSpecs.RW_PATHS
        return evaluateCheck(spec, { rootBeer.checkForRWPaths() }) { positive ->
            val output = ShellOutput.run("mount")
            val probes = RootBeerParsers.rwPathProbes(output, UpstreamConstants.pathsThatShouldNotBeWritable, Build.VERSION.SDK_INT)
            val findings = probes.filter { it.answer == ProbeAnswer.PRESENT }.map {
                Finding(
                    code = "rw-system-mount",
                    summary = "A system mount point is mounted rw",
                    strength = EvidenceStrength.MODERATE,
                    attributes = mapOf("mountPoint" to it.target),
                )
            }
            listOf(UnitEvaluation(spec.units.single().id, positive.toString(), positive, probes, findings))
        }
    }

    private fun testKeysCheck(): CheckEvaluation {
        val spec = RootBeerSpecs.TEST_KEYS
        return evaluateCheck(spec, { rootBeer.detectTestKeys() }) { positive ->
            val tags: String? = Build.TAGS
            val probe = when {
                tags == null -> ProbeResult("ro.build.tags", ProbeAnswer.NO_ANSWER, "build_tags_null")
                tags.contains("test-keys") -> ProbeResult("ro.build.tags", ProbeAnswer.PRESENT, tags)
                else -> ProbeResult("ro.build.tags", ProbeAnswer.ABSENT, tags)
            }
            val findings = listOfNotNull(
                Finding(
                    code = "test-keys",
                    summary = "Build.TAGS contains test-keys",
                    strength = EvidenceStrength.WEAK,
                    attributes = mapOf("buildTags" to tags.orEmpty()),
                ).takeIf { probe.answer == ProbeAnswer.PRESENT },
            )
            listOf(UnitEvaluation(spec.units.single().id, positive.toString(), positive, listOf(probe), findings))
        }
    }

    private fun whichSuCheck(): CheckEvaluation {
        val spec = RootBeerSpecs.WHICH_SU
        return evaluateCheck(spec, { rootBeer.checkSuExists() }) { positive ->
            val probe = RootBeerParsers.whichProbe(
                target = UpstreamConstants.BINARY_SU,
                output = ShellOutput.run("which", UpstreamConstants.BINARY_SU),
                anchor = ShellOutput.run("which", "sh"),
            )
            val findings = listOfNotNull(
                Finding(
                    code = "su-on-path",
                    summary = "`which su` resolved a path",
                    strength = EvidenceStrength.WEAK,
                    attributes = mapOf("path" to probe.reason),
                ).takeIf { probe.answer == ProbeAnswer.PRESENT },
            )
            listOf(UnitEvaluation(spec.units.single().id, positive.toString(), positive, listOf(probe), findings))
        }
    }

    /**
     * Grades a binary the shadow saw (Rule 6, as TamperProbe's SU_BINARY does): an executable
     * regular file in one of RootBeer's fixed directories is STRONG, anything else is WEAK.
     */
    private fun binaryFindings(
        directories: List<String>,
        probes: List<ProbeResult>,
        pathOf: (String) -> String,
    ): List<Finding> {
        val fixed = UpstreamConstants.fixedBinaryDirectories.toSet()
        val directoryOf = directories.associateBy(pathOf)
        return probes.filter { it.answer == ProbeAnswer.PRESENT }.map { probe ->
            val mode = PathProbe.modeOf(probe.target)
            val fixedPath = directoryOf[probe.target] in fixed
            val executable = PathProbe.isExecutableRegularFile(mode)
            Finding(
                code = if (fixedPath && executable) "executable-at-fixed-path" else "visible-path",
                summary = if (fixedPath && executable) {
                    "An executable regular file at a fixed RootBeer path"
                } else {
                    "A visible path RootBeer checks"
                },
                strength = if (fixedPath && executable) EvidenceStrength.STRONG else EvidenceStrength.WEAK,
                attributes = mapOf(
                    "path" to probe.target,
                    "source" to if (fixedPath) "fixed_path" else "environment_path",
                    "mode" to (mode?.let { Integer.toOctalString(it) } ?: "unknown"),
                ),
            )
        }
    }

    companion object {
        val UPSTREAM = UpstreamIdentity(
            name = "RootBeer",
            repository = "https://github.com/scottyab/rootbeer",
            revision = "de7bc7b4b09c9db148b62b331b4a44076b2eb480",
            aggregateMethod = "isRooted()",
        )

        /** The packages the host must declare under `<queries>`; RootBeer's manifest declares none. */
        fun declaredPackages(): Set<String> =
            (UpstreamConstants.rootManagementPackages + UpstreamConstants.dangerousPackages).toSet()
    }
}
