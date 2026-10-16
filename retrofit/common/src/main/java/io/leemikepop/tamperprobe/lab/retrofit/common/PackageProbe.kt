package io.leemikepop.tamperprobe.lab.retrofit.common

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

/**
 * Which packages the platform lets this host see at all, before any concealment.
 *
 * On Android 11 and later a package outside the host's visibility scope is reported as not
 * installed, which is exactly what an absent package gives. A negative for such a package is
 * therefore not an answer (Rule 1): the platform filtered the query, the package was not looked
 * at. The scope comes from the host's manifest, which no API exposes, so the host passes the
 * packages it declares under `<queries>`.
 */
sealed class PackageVisibilityScope {
    abstract val basis: String

    abstract fun covers(packageName: String): Boolean

    data class All(override val basis: String) : PackageVisibilityScope() {
        override fun covers(packageName: String): Boolean = true
    }

    data class Declared(val packages: Set<String>) : PackageVisibilityScope() {
        override val basis: String = "manifest_queries"

        override fun covers(packageName: String): Boolean = packageName in packages
    }

    companion object {
        fun resolve(context: Context, declaredPackages: Set<String>): PackageVisibilityScope = when {
            Build.VERSION.SDK_INT < Build.VERSION_CODES.R -> All("platform_below_api_30")
            context.applicationInfo.targetSdkVersion < Build.VERSION_CODES.R -> All("target_sdk_below_30")
            context.checkSelfPermission(QUERY_ALL_PACKAGES) == PackageManager.PERMISSION_GRANTED ->
                All("query_all_packages")
            else -> Declared(declaredPackages)
        }

        private const val QUERY_ALL_PACKAGES = Manifest.permission.QUERY_ALL_PACKAGES
    }
}

/**
 * Shadow probes for PackageManager channels.
 *
 * The anchor (Rule 2) is two packages every device has and every app can see: the host itself and
 * the platform package `android`. If either lookup fails, the PackageManager channel is not
 * answering and no "not installed" from it counts.
 */
object PackageProbe {
    const val PLATFORM_PACKAGE: String = "android"

    fun anchor(context: Context, call: (String) -> Unit): ProbeResult {
        for (packageName in listOf(context.packageName, PLATFORM_PACKAGE)) {
            val result = lookup(packageName, call)
            if (result.answer != ProbeAnswer.PRESENT) {
                return ProbeResult(packageName, ProbeAnswer.NO_ANSWER, "anchor_${result.reason}")
            }
        }
        return ProbeResult(PLATFORM_PACKAGE, ProbeAnswer.PRESENT, "ok")
    }

    /**
     * Runs [lookup] for one package. The lookup returns normally when the package is visible and
     * throws [PackageManager.NameNotFoundException] when it is reported as not installed.
     */
    fun lookup(packageName: String, call: (String) -> Unit): ProbeResult = try {
        call(packageName)
        ProbeResult(packageName, ProbeAnswer.PRESENT, "ok")
    } catch (_: PackageManager.NameNotFoundException) {
        ProbeResult(packageName, ProbeAnswer.ABSENT, "NameNotFoundException")
    } catch (error: RuntimeException) {
        ProbeResult(packageName, ProbeAnswer.NO_ANSWER, error.javaClass.simpleName)
    }

    /** Applies the visibility scope and the anchor to "not installed" answers. */
    fun qualify(
        probes: List<ProbeResult>,
        scope: PackageVisibilityScope,
        anchor: ProbeResult,
    ): List<ProbeResult> = probes.map { probe ->
        when {
            probe.answer != ProbeAnswer.ABSENT -> probe
            anchor.answer != ProbeAnswer.PRESENT -> probe.copy(answer = ProbeAnswer.NO_ANSWER, reason = anchor.reason)
            !scope.covers(probe.target) ->
                probe.copy(answer = ProbeAnswer.NO_ANSWER, reason = "outside_package_visibility_scope")
            else -> probe
        }
    }

    /** `getPackageInfo(name, 0)`, the lookup RootBeer makes. */
    fun packageInfoLookup(context: Context): (String) -> Unit = { name ->
        context.packageManager.getPackageInfo(name, 0)
    }
}
