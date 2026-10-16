package io.leemikepop.tamperprobe.lab.retrofit.rootbeer

import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.retrofit.common.CheckSpec
import io.leemikepop.tamperprobe.lab.retrofit.common.UnitSpec

/**
 * The nine checks `RootBeer.isRooted()` ORs together (revision de7bc7b), each declared as a
 * detector with one evidence unit per observation channel.
 *
 * Strengths follow TamperProbe's grading of the same evidence (Rule 6): a package name or a
 * development property is WEAK, an executable su at a fixed path is STRONG.
 */
internal object RootBeerSpecs {
    private const val PACKAGE_CONCEALMENT =
        "Per-app package-visibility concealment (Hide My Applist and similar) reports an installed " +
            "package as not installed, which is the same answer an absent package gives."
    private const val PATH_CONCEALMENT =
        "Unmounting root files in this app's mount namespace (Magisk DenyList, Shamiko, KernelSU " +
            "umount) and kernel path hiding (SUSFS sus_path) return ENOENT for a file that exists, " +
            "which is the same answer an absent file gives."
    private const val PROPERTY_CONCEALMENT =
        "Rewriting the property before Zygote starts (resetprop) gives this app the value an " +
            "unmodified device has."
    private const val MOUNT_CONCEALMENT =
        "A remount made in another mount namespace is not in this app's mount table; root hiding " +
            "gives the app the original namespace."

    val ROOT_MANAGEMENT_APPS = packageSpec(
        detectorId = "ROOTBEER_ROOT_MANAGEMENT_APPS",
        name = "RootBeer: root management apps",
        upstreamMethod = "detectRootManagementApps()",
        listName = "Const.knownRootAppsPackages",
    )

    val DANGEROUS_APPS = packageSpec(
        detectorId = "ROOTBEER_DANGEROUS_APPS",
        name = "RootBeer: potentially dangerous apps",
        upstreamMethod = "detectPotentiallyDangerousApps()",
        listName = "Const.knownDangerousAppsPackages",
    )

    val SU_BINARY = binarySpec("ROOTBEER_SU_BINARY", "su", "checkForBinary(\"su\")")

    val MAGISK_BINARY = binarySpec("ROOTBEER_MAGISK_BINARY", "magisk", "checkForMagiskBinary()")

    val DANGEROUS_PROPS = CheckSpec(
        detectorId = "ROOTBEER_DANGEROUS_PROPS",
        name = "RootBeer: dangerous properties",
        description = "RootBeer reads `getprop` output and flags ro.debuggable=1 or ro.secure=0.",
        domainId = "system-state",
        upstreamMethod = "checkForDangerousProps()",
        units = listOf(
            UnitSpec(
                id = "rootbeer-dangerous-props.getprop",
                title = "getprop output",
                observedObject = "ro.debuggable and ro.secure as listed by the getprop command",
                proposition = "ro.debuggable is 1 or ro.secure is 0",
                observationChannel = "Runtime.exec(\"getprop\") from the host process",
                availability = "Answers for a property only when getprop lists it; ro.build.version.sdk anchors the listing",
                trustBoundary = "Property service as seen by a command the app spawns",
                inferenceLimit = "Development builds and emulators set these values without root; " +
                    "a negative is concealable",
                concealment = PROPERTY_CONCEALMENT,
                fallbackStrength = EvidenceStrength.WEAK,
            ),
        ),
    )

    val RW_PATHS = CheckSpec(
        detectorId = "ROOTBEER_RW_PATHS",
        name = "RootBeer: system paths mounted read-write",
        description = "RootBeer reads `mount` output and flags a system mount point with the rw option.",
        domainId = "filesystem-state",
        upstreamMethod = "checkForRWPaths()",
        units = listOf(
            UnitSpec(
                id = "rootbeer-rw-paths.mount-table",
                title = "mount output",
                observedObject = "Mount options of seven system mount points",
                proposition = "A system mount point is mounted rw",
                observationChannel = "Runtime.exec(\"mount\") from the host process, parsed as RootBeer parses it",
                availability = "Answers only when the mount table was read and lists the root mount point",
                trustBoundary = "The host app's mount namespace",
                inferenceLimit = "A path that is not a mount point inherits its parent's options, which " +
                    "RootBeer does not check; a negative is concealable",
                concealment = MOUNT_CONCEALMENT,
                fallbackStrength = EvidenceStrength.MODERATE,
            ),
        ),
    )

    val TEST_KEYS = CheckSpec(
        detectorId = "ROOTBEER_TEST_KEYS",
        name = "RootBeer: test-keys build",
        description = "RootBeer flags a Build.TAGS value that contains test-keys.",
        domainId = "system-state",
        upstreamMethod = "detectTestKeys()",
        units = listOf(
            UnitSpec(
                id = "rootbeer-test-keys.build-tags",
                title = "Build.TAGS",
                observedObject = "android.os.Build.TAGS (ro.build.tags)",
                proposition = "The build is signed with test keys",
                observationChannel = "android.os.Build.TAGS, read by Zygote before the app starts",
                availability = "Answers whenever Build.TAGS is not null",
                trustBoundary = "Property values captured by Zygote",
                inferenceLimit = "Custom ROMs and engineering builds use test keys without root; a negative is concealable",
                concealment = PROPERTY_CONCEALMENT,
                fallbackStrength = EvidenceStrength.WEAK,
            ),
        ),
    )

    val WHICH_SU = CheckSpec(
        detectorId = "ROOTBEER_WHICH_SU",
        name = "RootBeer: su on PATH",
        description = "RootBeer runs `which su` and flags any output.",
        domainId = "binary-artifact",
        upstreamMethod = "checkSuExists()",
        units = listOf(
            UnitSpec(
                id = "rootbeer-which-su.which",
                title = "which su",
                observedObject = "An executable named su on the spawned shell's PATH",
                proposition = "su resolves on PATH",
                observationChannel = "Runtime.exec(\"which\", \"su\") from the host process",
                availability = "Answers only when `which sh` resolves through the same command",
                trustBoundary = "The PATH and mount namespace a command spawned by the app sees",
                inferenceLimit = "A su outside PATH is not seen; a negative is concealable",
                concealment = PATH_CONCEALMENT,
                fallbackStrength = EvidenceStrength.WEAK,
            ),
        ),
    )

    val NATIVE_SU = CheckSpec(
        detectorId = "ROOTBEER_NATIVE_SU",
        name = "RootBeer: native su check",
        description = "RootBeer's libtoolChecker.so calls fopen(path, \"r\") on su in every binary directory.",
        domainId = "binary-artifact",
        upstreamMethod = "checkForRootNative()",
        units = listOf(
            UnitSpec(
                id = "rootbeer-native-su.fopen",
                title = "fopen(\"r\") of su paths",
                observedObject = "A readable file named su in RootBeer's binary directories",
                proposition = "su can be opened for reading",
                observationChannel = "open(path, O_RDONLY) from native code; requires libtoolChecker.so to load",
                availability = "Answers only when the native library loaded and /system/bin/sh opens through the same call",
                trustBoundary = "The host app's mount namespace and SELinux domain",
                inferenceLimit = "A su that exists but is not readable by the app is not answered; a negative is concealable",
                concealment = PATH_CONCEALMENT,
                fallbackStrength = EvidenceStrength.WEAK,
            ),
        ),
    )

    /** In the order `isRooted()` evaluates them. */
    val ALL: List<CheckSpec> = listOf(
        ROOT_MANAGEMENT_APPS,
        DANGEROUS_APPS,
        SU_BINARY,
        DANGEROUS_PROPS,
        RW_PATHS,
        TEST_KEYS,
        WHICH_SU,
        NATIVE_SU,
        MAGISK_BINARY,
    )

    private fun packageSpec(
        detectorId: String,
        name: String,
        upstreamMethod: String,
        listName: String,
    ) = CheckSpec(
        detectorId = detectorId,
        name = name,
        description = "RootBeer calls getPackageInfo for every package in $listName.",
        domainId = "app-visibility",
        upstreamMethod = upstreamMethod,
        units = listOf(
            UnitSpec(
                id = "${detectorId.lowercase().replace('_', '-')}.package-manager",
                title = "PackageManager.getPackageInfo",
                observedObject = "Installed packages named in $listName",
                proposition = "A listed package is installed",
                observationChannel = "PackageManager.getPackageInfo(name, 0) from the host process",
                availability = "Answers for a package only inside the host's package-visibility scope, with the " +
                    "host and the android package anchoring the channel",
                trustBoundary = "system_server's package filtering for the host app",
                inferenceLimit = "A renamed or repackaged app is not seen; a negative is concealable",
                concealment = PACKAGE_CONCEALMENT,
                fallbackStrength = EvidenceStrength.WEAK,
            ),
        ),
    )

    private fun binarySpec(detectorId: String, binary: String, upstreamMethod: String) = CheckSpec(
        detectorId = detectorId,
        name = "RootBeer: $binary binary",
        description = "RootBeer calls File.exists() on $binary in its fixed directories and every PATH entry.",
        domainId = "binary-artifact",
        upstreamMethod = upstreamMethod,
        units = listOf(
            UnitSpec(
                id = "${detectorId.lowercase().replace('_', '-')}.file-exists",
                title = "File.exists() of $binary paths",
                observedObject = "A filesystem object named $binary in RootBeer's binary directories",
                proposition = "$binary exists in a binary directory",
                observationChannel = "java.io.File.exists(), which is stat(2); the shadow repeats the stat",
                availability = "Answers for a path when stat returns success, ENOENT or ENOTDIR and " +
                    "/system/bin/sh is visible through the same call",
                trustBoundary = "The host app's mount namespace and SELinux domain",
                inferenceLimit = "Existence alone does not show an executable; a negative is concealable",
                concealment = PATH_CONCEALMENT,
                fallbackStrength = EvidenceStrength.WEAK,
            ),
        ),
    )
}
