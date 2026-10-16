package io.leemikepop.tamperprobe.lab.retrofit.ruru

import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.retrofit.common.CheckSpec
import io.leemikepop.tamperprobe.lab.retrofit.common.UnitSpec

/**
 * The ten library checks Ruru's main page runs (30694c2), each declared as a detector.
 *
 * Ruru's page shows thirteen. Accessibility, SettingProp and Account are left out: their verdicts
 * are computed from values Ruru's app code collects (not by the library), they describe privacy
 * settings rather than root or hiding, and Account would put account names into the record.
 *
 * Ruru already has a coverage state, METHOD_UNAVAILABLE, which the retrofit keeps as "no answer".
 * What it lacks is a way to say that a check ran and answered "not found" only because concealment
 * made it so; and its libc file mode maps every errno, EACCES included, to NOT_FOUND.
 */
internal object RuruSpecs {
    private const val PACKAGE_CONCEALMENT =
        "Per-app package-visibility concealment (Hide My Applist and similar) removes an installed " +
            "package from every PackageManager answer to this app, which is the same answer an absent package gives."
    private const val PATH_CONCEALMENT =
        "Unmounting or hiding paths for this app (Magisk DenyList, Shamiko, KernelSU umount, SUSFS " +
            "sus_path) returns ENOENT for a path that exists, which is the same answer an absent path gives."
    private const val XPOSED_CONCEALMENT =
        "An Xposed framework that renames or hides the classes xposed-detector looks up leaves a hooked " +
            "process looking unhooked; the xposed-control ladder cell tests this declaration."

    private const val APP_VISIBILITY = "app-visibility"

    val ABNORMAL_ENVIRONMENT = CheckSpec(
        detectorId = "RURU_ABNORMAL_ENVIRONMENT",
        name = "Ruru: abnormal environment",
        description = "Ruru's AbnormalEnvironment: Xposed hooks in the process, a secondary user " +
            "profile, marker files of hiding tools, and su, busybox and magisk in ten directories.",
        domainId = "filesystem-state",
        upstreamMethod = "AbnormalEnvironment.run(null, detail)",
        units = listOf(
            UnitSpec(
                id = "ruru-abnormal-environment.xposed-hooks",
                title = "xposed-detector status",
                observedObject = "Xposed hooks in the host process",
                proposition = "An Xposed environment is present in the process",
                observationChannel = "xposed-detector get_xposed_status() from Ruru's native library",
                availability = "Always answers; the library inspects its own process",
                trustBoundary = "The host process's runtime",
                inferenceLimit = "Loading the library clears hooks it recognises; a negative is concealable",
                concealment = XPOSED_CONCEALMENT,
                fallbackStrength = EvidenceStrength.MODERATE,
            ),
            UnitSpec(
                id = "ruru-abnormal-environment.user-profile",
                title = "Files directory owner",
                observedObject = "The user the host's files directory belongs to",
                proposition = "The host runs in a secondary user or work profile",
                observationChannel = "Context.getFilesDir() path prefix",
                availability = "Always answers",
                trustBoundary = "The host's own context",
                inferenceLimit = "A secondary profile is not tampering; Ruru reports it as suspicious",
                concealment = null,
                fallbackStrength = EvidenceStrength.WEAK,
            ),
            UnitSpec(
                id = "ruru-abnormal-environment.marker-files",
                title = "Hiding-tool marker files",
                observedObject = "Seven files left by Hide My Applist (old), XPrivacyLua, TWRP, Xposed Edge, " +
                    "Riru Clipboard and PrivacySpace",
                proposition = "A marker file exists",
                observationChannel = "raw faccessat (libc access/stat/open(O_PATH) after SIGSYS), as detectFile",
                availability = "Answers for a path on ENOENT or ENOTDIR, with /system/bin/sh visible through the same call",
                trustBoundary = "The host app's mount namespace and SELinux domain",
                inferenceLimit = "Most markers lie under /data/system or /data/misc, which apps cannot search; " +
                    "a negative is concealable",
                concealment = PATH_CONCEALMENT,
                fallbackStrength = EvidenceStrength.WEAK,
            ),
            UnitSpec(
                id = "ruru-abnormal-environment.root-binaries",
                title = "su, busybox and magisk files",
                observedObject = "Files named su, busybox or magisk in Ruru's ten directories",
                proposition = "A root binary exists",
                observationChannel = "raw faccessat (libc access/stat/open(O_PATH) after SIGSYS), as detectFile",
                availability = "Answers for a path on ENOENT or ENOTDIR, with /system/bin/sh visible through the same call",
                trustBoundary = "The host app's mount namespace and SELinux domain",
                inferenceLimit = "Ruru checks \"/cache\" + name (no slash); a negative is concealable",
                concealment = PATH_CONCEALMENT,
                fallbackStrength = EvidenceStrength.WEAK,
            ),
        ),
    )

    val PM_COMMAND = pmSpec(
        detectorId = "RURU_PM_COMMAND",
        name = "Ruru: pm list packages",
        upstream = "PMCommand",
        channel = "Runtime.exec(\"pm list packages\") from the host process",
        availability = "Answers only when the listing contains the host and the android package",
    )

    val PM_CONVENTIONAL_APIS = pmSpec(
        detectorId = "RURU_PM_CONVENTIONAL_APIS",
        name = "Ruru: installed packages and applications",
        upstream = "PMConventionalAPIs",
        channel = "PackageManager.getInstalledPackages(0) and getInstalledApplications(0)",
        availability = "Answers only when the listing contains the host and the android package",
    )

    val PM_SUNDRY_APIS = pmSpec(
        detectorId = "RURU_PM_SUNDRY_APIS",
        name = "Ruru: package lookups",
        upstream = "PMSundryAPIs",
        channel = "PackageManager.getPackageUid, getInstallSourceInfo and getLaunchIntentForPackage",
        availability = "Answers only when getPackageUid resolves the host and the android package",
    )

    val PM_INTENT_QUERIES = pmSpec(
        detectorId = "RURU_PM_INTENT_QUERIES",
        name = "Ruru: launcher intent query",
        upstream = "PMQueryIntentActivities",
        channel = "PackageManager.queryIntentActivities(ACTION_MAIN, MATCH_ALL)",
        availability = "Answers only when the result contains the host's own MAIN activity",
        limit = "A package without a MAIN activity is never listed, installed or not; a negative is concealable",
    )

    val FILE_LIBC = fileSpec(
        detectorId = "RURU_FILE_LIBC",
        name = "Ruru: libc file detection",
        upstream = "FileDetection(useSyscall = false)",
        channel = "access(F_OK), stat and fstat(open(O_PATH)) on six data paths per package",
    )

    val FILE_SYSCALL = fileSpec(
        detectorId = "RURU_FILE_SYSCALL",
        name = "Ruru: syscall file detection",
        upstream = "FileDetection(useSyscall = true)",
        channel = "raw faccessat(AT_FDCWD, path, F_OK) on six data paths per package",
    )

    val XPOSED_MODULES = launcherSpec(
        detectorId = "RURU_XPOSED_MODULES",
        name = "Ruru: Xposed modules",
        upstream = "XposedModules(lspatch = false)",
        observed = "Xposed module metadata and META-INF/xposed/module.prop in launcher apps",
        proposition = "A launcher app is an Xposed module",
        strength = EvidenceStrength.WEAK,
    )

    val LSPATCH = launcherSpec(
        detectorId = "RURU_LSPATCH",
        name = "Ruru: LSPatch apps",
        upstream = "XposedModules(lspatch = true)",
        observed = "LSPatch, NPatch or JsHook metadata and an LSPosed component factory in launcher apps",
        proposition = "A launcher app is patched with LSPatch or a derivative",
        strength = EvidenceStrength.WEAK,
    )

    val MAGISK_APP = CheckSpec(
        detectorId = "RURU_MAGISK_APP",
        name = "Ruru: repackaged Magisk app",
        description = "Ruru's MagiskApp compares every launcher app's size, components and permissions " +
            "with the Magisk stub APK shipped in its assets.",
        domainId = APP_VISIBILITY,
        upstreamMethod = "MagiskApp.run(null, detail)",
        units = listOf(
            UnitSpec(
                id = "ruru-magisk-app.stub-shape",
                title = "Stub-shaped launcher apps",
                observedObject = "Non-system launcher apps whose size and components match the Magisk stub",
                proposition = "A launcher app is a repackaged Magisk app",
                observationChannel = "queryIntentActivities(ACTION_MAIN) and getPackageInfo per app, " +
                    "compared with getPackageArchiveInfo(assets/stub.apk)",
                availability = "Answers only when the stub reference parses and the host is listed; an app whose " +
                    "comparison throws is not answered",
                trustBoundary = "system_server's package filtering for the host app",
                inferenceLimit = "Upstream swallows every per-app exception, including a missing stub; " +
                    "a negative is concealable",
                concealment = PACKAGE_CONCEALMENT,
                fallbackStrength = EvidenceStrength.MODERATE,
                redactTargets = true,
            ),
        ),
    )

    /** In the order Ruru's main page runs them. */
    val ALL: List<CheckSpec> = listOf(
        ABNORMAL_ENVIRONMENT,
        PM_COMMAND,
        PM_CONVENTIONAL_APIS,
        PM_SUNDRY_APIS,
        PM_INTENT_QUERIES,
        FILE_LIBC,
        FILE_SYSCALL,
        XPOSED_MODULES,
        LSPATCH,
        MAGISK_APP,
    )

    fun unitId(detectorId: String, channel: String): String = "${detectorId.lowercase().replace('_', '-')}.$channel"

    private fun pmSpec(
        detectorId: String,
        name: String,
        upstream: String,
        channel: String,
        availability: String,
        limit: String = "A renamed or repackaged app is not seen; a negative is concealable",
    ) = CheckSpec(
        detectorId = detectorId,
        name = name,
        description = "Ruru's $upstream: whether any of its eleven basic packages is visible, and whether " +
            "the listing holds only the host itself.",
        domainId = APP_VISIBILITY,
        upstreamMethod = "$upstream.run(basicAppList, detail)",
        units = listOf(
            UnitSpec(
                id = unitId(detectorId, "package-manager"),
                title = name.substringAfter(": "),
                observedObject = "Ruru's basic package list",
                proposition = "A listed package is installed",
                observationChannel = channel,
                availability = availability,
                trustBoundary = "system_server's package filtering for the host app",
                inferenceLimit = limit,
                concealment = PACKAGE_CONCEALMENT,
                fallbackStrength = EvidenceStrength.WEAK,
            ),
        ),
    )

    private fun fileSpec(detectorId: String, name: String, upstream: String, channel: String) = CheckSpec(
        detectorId = detectorId,
        name = name,
        description = "Ruru's $upstream: whether a data directory of any basic package is visible.",
        domainId = APP_VISIBILITY,
        upstreamMethod = "$upstream.run(basicAppList, detail)",
        units = listOf(
            UnitSpec(
                id = unitId(detectorId, "app-data-paths"),
                title = "App data paths",
                observedObject = "/data/data, /data/user_de/0, /data/misc/profiles/ref and " +
                    "Android/{data,media,obb} directories of the basic packages",
                proposition = "A data directory of a listed package exists",
                observationChannel = channel,
                availability = "Answers for a path family only when com.android.settings' directory in that " +
                    "family is visible through the same call (app data isolation hides it otherwise)",
                trustBoundary = "The host app's mount namespace, SELinux domain and storage view",
                inferenceLimit = "A leftover directory does not show an installed app; a negative is concealable",
                concealment = PATH_CONCEALMENT,
                fallbackStrength = EvidenceStrength.WEAK,
            ),
        ),
    )

    private fun launcherSpec(
        detectorId: String,
        name: String,
        upstream: String,
        observed: String,
        proposition: String,
        strength: EvidenceStrength,
    ) = CheckSpec(
        detectorId = detectorId,
        name = name,
        description = "Ruru's $upstream over every app with a MAIN activity.",
        domainId = APP_VISIBILITY,
        upstreamMethod = "$upstream.run(null, detail)",
        units = listOf(
            UnitSpec(
                id = unitId(detectorId, "launcher-apps"),
                title = "Launcher apps",
                observedObject = observed,
                proposition = proposition,
                observationChannel = "queryIntentActivities(ACTION_MAIN, GET_META_DATA), then each app's metadata and APK",
                availability = "Answers for an app whose APK and metadata could be read, when the host itself is listed",
                trustBoundary = "system_server's package filtering for the host app",
                inferenceLimit = "A module without a MAIN activity is never listed; a negative is concealable",
                concealment = PACKAGE_CONCEALMENT,
                fallbackStrength = strength,
                redactTargets = true,
            ),
        ),
    )
}
