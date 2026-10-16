package io.leemikepop.tamperprobe.lab.retrofit.ruru

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import icu.nullptr.applistdetector.AbnormalEnvironment
import icu.nullptr.applistdetector.FileDetection
import icu.nullptr.applistdetector.IDetector
import icu.nullptr.applistdetector.MagiskApp
import icu.nullptr.applistdetector.PMCommand
import icu.nullptr.applistdetector.PMConventionalAPIs
import icu.nullptr.applistdetector.PMQueryIntentActivities
import icu.nullptr.applistdetector.PMSundryAPIs
import icu.nullptr.applistdetector.XposedModules
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
import io.leemikepop.tamperprobe.lab.retrofit.common.timedMicros
import java.io.File
import java.util.zip.ZipFile

/**
 * Reports Ruru's library checks through the Evidence Contract.
 *
 * Each check is the unmodified upstream detector, run with the same arguments Ruru's main page
 * passes. Its `Result` is the upstream verdict and decides every positive (FOUND and SUSPICIOUS);
 * METHOD_UNAVAILABLE is kept as "no answer". Shadow probes repeat the detector's calls to learn
 * what Ruru discards: which NOT_FOUND came from a channel that answered.
 */
class RuruRetrofit(private val context: Context) {
    private val packageScope = PackageVisibilityScope.resolve(context, emptySet())

    val packageVisibility: String
        get() = when (val scope = packageScope) {
            is PackageVisibilityScope.All -> scope.basis
            is PackageVisibilityScope.Declared -> "${scope.basis}:${scope.packages.size}"
        }

    fun evaluate(): List<CheckEvaluation> = listOf(
        abnormalEnvironment(),
        packageList(RuruSpecs.PM_COMMAND, PMCommand(context, NAME), ::pmCommandListing),
        packageList(RuruSpecs.PM_CONVENTIONAL_APIS, PMConventionalAPIs(context, NAME), ::conventionalListing),
        pmSundry(),
        packageList(RuruSpecs.PM_INTENT_QUERIES, PMQueryIntentActivities(context, NAME), ::intentListing),
        fileDetection(RuruSpecs.FILE_LIBC, useSyscall = false),
        fileDetection(RuruSpecs.FILE_SYSCALL, useSyscall = true),
        launcherApps(RuruSpecs.XPOSED_MODULES, XposedModules(context, NAME, false), ::xposedModuleShape),
        launcherApps(RuruSpecs.LSPATCH, XposedModules(context, NAME, true), ::lspatchShape),
        magiskApp(),
    )

    /** Ruru has no single verdict; its page shows each check. The highest result stands in for one. */
    fun aggregateVerdict(evaluations: List<CheckEvaluation>): String =
        evaluations.mapNotNull { evaluation ->
            IDetector.Result.values().firstOrNull { it.name == evaluation.upstreamVerdict }
        }.maxOrNull()?.name ?: "none"

    private class UpstreamRun(val result: IDetector.Result, val detail: List<Pair<String, IDetector.Result>>) {
        fun itemResult(name: String): IDetector.Result =
            detail.filter { it.first == name }.maxOfOrNull { it.second } ?: IDetector.Result.NOT_FOUND
    }

    private fun check(
        spec: CheckSpec,
        upstream: () -> UpstreamRun,
        evaluate: (UpstreamRun) -> List<UnitEvaluation>,
    ): CheckEvaluation {
        val (evaluation, micros) = timedMicros {
            runCatching(upstream).fold(
                onSuccess = { run -> CheckEvaluation(spec, run.result.name, run.result.positive, evaluate(run)) },
                onFailure = { CheckEvaluation(spec, "threw", false, emptyList(), upstreamFailure = it) },
            )
        }
        return evaluation.copy(durationMicros = micros)
    }

    private fun run(detector: IDetector, packages: Collection<String>?): UpstreamRun {
        val detail = mutableListOf<Pair<String, IDetector.Result>>()
        val result = detector.run(packages, detail)
        return UpstreamRun(result, detail)
    }

    // ---- AbnormalEnvironment ----------------------------------------------------------------

    private fun abnormalEnvironment(): CheckEvaluation {
        val spec = RuruSpecs.ABNORMAL_ENVIRONMENT
        return check(spec, { run(AbnormalEnvironment(context, NAME), null) }) { upstream ->
            val anchor = RuruShadow.detectFile(PathProbe.ANCHOR_PATH)
            listOf(
                xposedHooksUnit(spec, upstream),
                userProfileUnit(spec, upstream),
                markerFilesUnit(spec, upstream, anchor),
                rootBinariesUnit(spec, upstream, anchor),
            )
        }
    }

    private fun xposedHooksUnit(spec: CheckSpec, upstream: UpstreamRun): UnitEvaluation {
        val result = upstream.itemResult("Xposed hooks")
        // The library's status is the only view of this channel; it always answers.
        val probe = ProbeResult(
            "host-process",
            if (result.positive) ProbeAnswer.PRESENT else ProbeAnswer.ABSENT,
            if (result.positive) "xposed_status_found" else "NO_XPOSED",
        )
        val findings = listOfNotNull(
            Finding(
                "xposed-environment",
                "xposed-detector found an Xposed environment in the process",
                EvidenceStrength.MODERATE,
            ).takeIf { result.positive },
        )
        return UnitEvaluation(spec.units[0].id, result.name, result.positive, listOf(probe), findings)
    }

    private fun userProfileUnit(spec: CheckSpec, upstream: UpstreamRun): UnitEvaluation {
        val result = upstream.itemResult("Dual / Work profile")
        val probe = ProbeResult(
            context.filesDir.path,
            if (result.positive) ProbeAnswer.PRESENT else ProbeAnswer.ABSENT,
            "files_dir",
        )
        val findings = listOfNotNull(
            Finding("secondary-profile", "The host runs outside user 0", EvidenceStrength.WEAK)
                .takeIf { result.positive },
        )
        return UnitEvaluation(spec.units[1].id, result.name, result.positive, listOf(probe), findings)
    }

    private fun markerFilesUnit(spec: CheckSpec, upstream: UpstreamRun, anchor: ProbeResult): UnitEvaluation {
        val items = RuruConstants.MARKER_FILES
        val results = items.keys.map(upstream::itemResult)
        val verdict = results.maxOrNull() ?: IDetector.Result.NOT_FOUND
        val probes = PathProbe.anchored(anchor, items.values.flatten().map(RuruShadow::detectFile))
        val present = probes.filter { it.answer == ProbeAnswer.PRESENT }.map { it.target }.toSet()
        val findings = items.filterKeys { upstream.itemResult(it).positive }.map { (item, paths) ->
            Finding(
                code = "marker-file",
                summary = "A hiding-tool marker file is visible",
                strength = EvidenceStrength.WEAK,
                attributes = mapOf("item" to item, "paths" to paths.filter { it in present }.joinToString(",")),
            )
        }
        return UnitEvaluation(spec.units[2].id, verdict.name, verdict.positive, probes, findings)
    }

    private fun rootBinariesUnit(spec: CheckSpec, upstream: UpstreamRun, anchor: ProbeResult): UnitEvaluation {
        val items = RuruConstants.ROOT_BINARY_ITEMS
        val verdict = items.keys.map(upstream::itemResult).maxOrNull() ?: IDetector.Result.NOT_FOUND
        val paths = items.values.flatMap { binary -> RuruConstants.ROOT_BINARY_PLACES.map { it + binary } }
        val probes = PathProbe.anchored(anchor, paths.map(RuruShadow::detectFile))
        val findings = items.filterKeys { upstream.itemResult(it).positive }.flatMap { (item, binary) ->
            val seen = probes.filter { it.answer == ProbeAnswer.PRESENT && it.target.endsWith(binary) }
            seen.map { probe ->
                val executable = PathProbe.isExecutableRegularFile(PathProbe.modeOf(probe.target))
                // As TamperProbe grades BUSYBOX: never above WEAK.
                val strong = executable && binary != "busybox"
                Finding(
                    code = if (strong) "executable-root-binary" else "visible-root-binary",
                    summary = if (strong) "An executable $binary is visible" else "A path named $binary is visible",
                    strength = if (strong) EvidenceStrength.STRONG else EvidenceStrength.WEAK,
                    attributes = mapOf("item" to item, "path" to probe.target, "shadow" to probe.reason),
                )
            }.ifEmpty {
                listOf(Finding("visible-root-binary", "Ruru reported $item", EvidenceStrength.WEAK, mapOf("item" to item)))
            }
        }
        return UnitEvaluation(spec.units[3].id, verdict.name, verdict.positive, probes, findings)
    }

    // ---- PackageManager checks ---------------------------------------------------------------

    /** A listing check: one call returns a set of package names, each target is looked up in it. */
    private fun packageList(
        spec: CheckSpec,
        detector: IDetector,
        listing: () -> Set<String>?,
    ): CheckEvaluation = check(spec, { run(detector, RuruConstants.BASIC_APP_LIST) }) { upstream ->
        val packages = runCatching(listing)
        val set = packages.getOrNull()
        val anchor = when {
            set == null -> ProbeResult("listing", ProbeAnswer.NO_ANSWER, "listing_${packages.exceptionOrNull()?.javaClass?.simpleName}")
            context.packageName !in set -> ProbeResult(context.packageName, ProbeAnswer.NO_ANSWER, "anchor_host_not_listed")
            spec != RuruSpecs.PM_INTENT_QUERIES && PackageProbe.PLATFORM_PACKAGE !in set ->
                ProbeResult(PackageProbe.PLATFORM_PACKAGE, ProbeAnswer.NO_ANSWER, "anchor_android_not_listed")
            else -> ProbeResult("listing", ProbeAnswer.PRESENT, "ok")
        }
        val probes = RuruConstants.BASIC_APP_LIST.map { name ->
            if (set != null && name in set) {
                ProbeResult(name, ProbeAnswer.PRESENT, "listed")
            } else {
                ProbeResult(name, ProbeAnswer.ABSENT, "not_listed")
            }
        }
        listOf(packageUnit(spec, upstream, PackageProbe.qualify(probes, packageScope, anchor), set?.size))
    }

    private fun pmSundry(): CheckEvaluation {
        val spec = RuruSpecs.PM_SUNDRY_APIS
        return check(spec, { run(PMSundryAPIs(context, NAME), RuruConstants.BASIC_APP_LIST) }) { upstream ->
            val pm = context.packageManager
            val anchor = PackageProbe.anchor(context) { pm.getPackageUid(it, 0) }
            val probes = RuruConstants.BASIC_APP_LIST.map { name ->
                // PMSundryAPIs counts a package found if any of its three lookups succeeds.
                val lookups = listOf<(String) -> Unit>(
                    { pm.getPackageUid(it, 0) },
                    { pm.getInstallSourceInfo(it) },
                    { if (pm.getLaunchIntentForPackage(it) == null) throw PackageManager.NameNotFoundException(it) },
                ).map { PackageProbe.lookup(name, it) }
                lookups.firstOrNull { it.answer == ProbeAnswer.PRESENT }
                    ?: lookups.firstOrNull { it.answer == ProbeAnswer.NO_ANSWER }
                    ?: lookups.first()
            }
            listOf(packageUnit(spec, upstream, PackageProbe.qualify(probes, packageScope, anchor), null))
        }
    }

    private fun packageUnit(
        spec: CheckSpec,
        upstream: UpstreamRun,
        qualified: List<ProbeResult>,
        listingSize: Int?,
    ): UnitEvaluation {
        val probes = if (upstream.result == IDetector.Result.METHOD_UNAVAILABLE) {
            qualified.map { it.copy(answer = ProbeAnswer.NO_ANSWER, reason = "upstream_method_unavailable") }
        } else {
            qualified
        }
        val found = upstream.detail.filter { it.second == IDetector.Result.FOUND }.map { it.first }
        val findings = found.map {
            Finding("installed-package", "A package on Ruru's basic list is visible", EvidenceStrength.WEAK, mapOf("packageName" to it))
        } + listOfNotNull(
            Finding(
                code = "only-self-visible",
                summary = "The listing holds a single package, which Ruru reports as suspicious",
                strength = EvidenceStrength.WEAK,
                attributes = mapOf("listingSize" to (listingSize?.toString() ?: "unknown")),
            ).takeIf { upstream.result == IDetector.Result.SUSPICIOUS && found.isEmpty() },
        )
        return UnitEvaluation(spec.units.single().id, upstream.result.name, upstream.result.positive, probes, findings)
    }

    private fun pmCommandListing(): Set<String>? {
        val output = ShellOutput.run("pm", "list", "packages")
        if (output.noAnswerReason != null) return null
        return RuruParsers.parsePmList(output.lines)
    }

    @SuppressLint("QueryPermissionsNeeded")
    private fun conventionalListing(): Set<String> {
        val pm = context.packageManager
        return pm.getInstalledPackages(0).map { it.packageName }.toSet() +
            pm.getInstalledApplications(0).map { it.packageName }
    }

    @SuppressLint("QueryPermissionsNeeded")
    private fun intentListing(): Set<String> = context.packageManager
        .queryIntentActivities(Intent(Intent.ACTION_MAIN), PackageManager.MATCH_ALL)
        .map { it.activityInfo.packageName }
        .toSet()

    // ---- FileDetection -----------------------------------------------------------------------

    private fun fileDetection(spec: CheckSpec, useSyscall: Boolean): CheckEvaluation =
        check(spec, { run(FileDetection(context, useSyscall, NAME), RuruConstants.BASIC_APP_LIST) }) { upstream ->
            val probe: (String) -> ProbeResult = if (useSyscall) RuruShadow::syscall else RuruShadow::libc
            val controls = RuruConstants.DATA_PATH_FAMILIES.associateWith { probe(it.format(SETTINGS_PACKAGE)) }
            val unavailable = upstream.detail.filter { it.second == IDetector.Result.METHOD_UNAVAILABLE }.map { it.first }.toSet()
            val probes = RuruConstants.BASIC_APP_LIST.flatMap { name ->
                RuruConstants.DATA_PATH_FAMILIES.map { family ->
                    val result = probe(family.format(name))
                    val control = controls.getValue(family)
                    when {
                        name in unavailable -> result.copy(answer = ProbeAnswer.NO_ANSWER, reason = "upstream_method_unavailable")
                        result.answer == ProbeAnswer.ABSENT && control.answer != ProbeAnswer.PRESENT ->
                            result.copy(answer = ProbeAnswer.NO_ANSWER, reason = "control_${control.reason}")
                        else -> result
                    }
                }
            }
            val present = probes.filter { it.answer == ProbeAnswer.PRESENT }
            val findings = upstream.detail.filter { it.second.positive }.map { (name, result) ->
                Finding(
                    code = "app-data-path",
                    summary = "A data directory of a package on Ruru's basic list is visible",
                    strength = EvidenceStrength.WEAK,
                    attributes = mapOf(
                        "packageName" to name,
                        "upstreamResult" to result.name,
                        "paths" to present.filter { it.target.endsWith("/$name") }.joinToString(",") { it.target },
                    ),
                )
            }
            listOf(UnitEvaluation(spec.units.single().id, upstream.result.name, upstream.result.positive, probes, findings))
        }

    // ---- Launcher-app checks -----------------------------------------------------------------

    @SuppressLint("QueryPermissionsNeeded")
    private fun launcherApplications(flags: Int): List<ApplicationInfo> = context.packageManager
        .queryIntentActivities(Intent(Intent.ACTION_MAIN), flags)
        .map { it.activityInfo.applicationInfo }
        .distinctBy { it.packageName }

    /**
     * XposedModules: each launcher app is a target. An app whose APK cannot be opened is not
     * answered, because upstream silently treats that as "no module.prop".
     */
    private fun launcherApps(
        spec: CheckSpec,
        detector: IDetector,
        shape: (ApplicationInfo) -> ProbeAnswer,
    ): CheckEvaluation = check(spec, { run(detector, null) }) { upstream ->
        val apps = runCatching { launcherApplications(PackageManager.GET_META_DATA) }
        val list = apps.getOrNull().orEmpty()
        val anchored = list.any { it.packageName == context.packageName }
        val probes = list.map { app ->
            val answer = runCatching { shape(app) }
            when {
                answer.isFailure -> ProbeResult(app.packageName, ProbeAnswer.NO_ANSWER, answer.exceptionOrNull()!!.javaClass.simpleName)
                !anchored && answer.getOrThrow() == ProbeAnswer.ABSENT ->
                    ProbeResult(app.packageName, ProbeAnswer.NO_ANSWER, "anchor_host_not_listed")
                else -> ProbeResult(app.packageName, answer.getOrThrow(), "metadata_read")
            }
        }.ifEmpty {
            listOf(ProbeResult("launcher-apps", ProbeAnswer.NO_ANSWER, "listing_${apps.exceptionOrNull()?.javaClass?.simpleName ?: "empty"}"))
        }
        val findings = upstream.detail.filter { it.second.positive }.map { (label, _) ->
            Finding("module-app", "Ruru reported a launcher app as a module or patched app", spec.units.single().fallbackStrength, mapOf("label" to label))
        }
        listOf(UnitEvaluation(spec.units.single().id, upstream.result.name, upstream.result.positive, probes, findings))
    }

    /** XposedModules(lspatch = false)'s test; ZipFile throws when the APK cannot be opened. */
    private fun xposedModuleShape(app: ApplicationInfo): ProbeAnswer {
        val meta = app.metaData
        val xposedMeta = listOf("xposedminversion", "xposeddescription").any { meta?.containsKey(it) == true }
        val lspatchMeta = listOf("lspatch", "npatch", "jshook").any { meta?.containsKey(it) == true }
        val modulePropPresent = ZipFile(app.sourceDir).use { it.getEntry("META-INF/xposed/module.prop") != null }
        return if ((xposedMeta || modulePropPresent) && !lspatchMeta) ProbeAnswer.PRESENT else ProbeAnswer.ABSENT
    }

    /** XposedModules(lspatch = true)'s test. */
    private fun lspatchShape(app: ApplicationInfo): ProbeAnswer {
        val meta = app.metaData
        val lspatchMeta = listOf("lspatch", "npatch", "jshook").any { meta?.containsKey(it) == true }
        val factory = app.appComponentFactory?.contains("lsposed") == true
        return if (lspatchMeta || factory) ProbeAnswer.PRESENT else ProbeAnswer.ABSENT
    }

    // ---- MagiskApp ---------------------------------------------------------------------------

    private fun magiskApp(): CheckEvaluation {
        val spec = RuruSpecs.MAGISK_APP
        return check(spec, { run(MagiskApp(context, NAME), null) }) { upstream ->
            val stub = runCatching { stubReference() }
            val apps = runCatching { launcherApplications(PackageManager.MATCH_ALL) }.getOrNull().orEmpty()
            val anchored = apps.any { it.packageName == context.packageName }
            val probes = when {
                stub.getOrNull() == null -> apps.map {
                    ProbeResult(it.packageName, ProbeAnswer.NO_ANSWER, "stub_reference_${stub.exceptionOrNull()?.javaClass?.simpleName ?: "null"}")
                }
                else -> apps.map { app ->
                    val answer = runCatching { stubShape(app.packageName, stub.getOrThrow()!!) }
                    when {
                        answer.isFailure -> ProbeResult(app.packageName, ProbeAnswer.NO_ANSWER, answer.exceptionOrNull()!!.javaClass.simpleName)
                        !anchored && answer.getOrThrow() == ProbeAnswer.ABSENT ->
                            ProbeResult(app.packageName, ProbeAnswer.NO_ANSWER, "anchor_host_not_listed")
                        else -> ProbeResult(app.packageName, answer.getOrThrow(), "compared")
                    }
                }
            }.ifEmpty { listOf(ProbeResult("launcher-apps", ProbeAnswer.NO_ANSWER, "listing_empty")) }
            val findings = upstream.detail.filter { it.second.positive }.map { (name, _) ->
                Finding("stub-shaped-app", "A launcher app has the Magisk stub's shape", EvidenceStrength.MODERATE, mapOf("packageName" to name))
            }
            listOf(UnitEvaluation(spec.units.single().id, upstream.result.name, upstream.result.positive, probes, findings))
        }
    }

    private fun stubReference(): PackageInfo? {
        val archive = context.cacheDir.resolve("stub-shadow.apk")
        context.assets.open("stub.apk").use { input -> archive.outputStream().use { input.copyTo(it) } }
        return context.packageManager.getPackageArchiveInfo(archive.absolutePath, MAGISK_FLAGS)
    }

    /** MagiskApp's comparison, with its exceptions surfaced instead of swallowed. */
    private fun stubShape(packageName: String, stub: PackageInfo): ProbeAnswer {
        val info = context.packageManager.getPackageInfo(packageName, MAGISK_FLAGS)
        val app = info.applicationInfo!!
        val apkSize = File(app.sourceDir).length() / 1024
        if (apkSize !in 20..40 && apkSize !in 9 * 1024..20 * 1024) return ProbeAnswer.ABSENT
        if (app.flags and ApplicationInfo.FLAG_SYSTEM != 0) return ProbeAnswer.ABSENT
        if (info.activities!!.size != stub.activities!!.size) return ProbeAnswer.ABSENT
        if (info.services!!.size != stub.services!!.size) return ProbeAnswer.ABSENT
        if (info.receivers!!.size != stub.receivers!!.size) return ProbeAnswer.ABSENT
        if (info.providers!!.size != stub.providers!!.size) return ProbeAnswer.ABSENT
        val stubPermissions = stub.requestedPermissions!!.toMutableSet()
        stubPermissions.remove("com.android.launcher.permission.INSTALL_SHORTCUT")
        return if (info.requestedPermissions!!.toSet().containsAll(stubPermissions)) ProbeAnswer.PRESENT else ProbeAnswer.ABSENT
    }

    companion object {
        val UPSTREAM = UpstreamIdentity(
            name = "Ruru",
            repository = "https://github.com/byxiaorun/Ruru",
            revision = "30694c211c63e8bc48c4db84a1cb525868c2bc41",
            aggregateMethod = "max(Result) over the checks",
        )

        /** Detector names are display strings in Ruru; the retrofit's own names are in the specs. */
        private const val NAME = "retrofit"
        private const val SETTINGS_PACKAGE = "com.android.settings"

        private val MAGISK_FLAGS = PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
            PackageManager.GET_PROVIDERS or PackageManager.GET_RECEIVERS or
            PackageManager.MATCH_DIRECT_BOOT_AWARE or PackageManager.MATCH_DIRECT_BOOT_UNAWARE or
            PackageManager.GET_PERMISSIONS
    }
}

internal val IDetector.Result.positive: Boolean
    get() = this == IDetector.Result.FOUND || this == IDetector.Result.SUSPICIOUS
