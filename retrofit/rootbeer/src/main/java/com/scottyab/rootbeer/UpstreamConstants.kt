package com.scottyab.rootbeer

/**
 * Read-only access to RootBeer's package-private constants, so the shadow probes use exactly the
 * targets the upstream checks use. This file is part of the retrofit, not of RootBeer: it lives in
 * RootBeer's package only because Kotlin can read package-private Java members from there.
 */
object UpstreamConstants {
    const val BINARY_SU: String = Const.BINARY_SU

    /** `Const.getPaths()`: the fixed su directories plus every `$PATH` entry, as RootBeer builds it. */
    fun binaryDirectories(): List<String> = Const.getPaths().toList()

    /** The fixed part of [binaryDirectories] (`Const.suPaths`, which is private). */
    val fixedBinaryDirectories: List<String> by lazy {
        val field = Const::class.java.getDeclaredField("suPaths")
        field.isAccessible = true
        (field.get(null) as Array<*>).map { it as String }
    }

    val rootManagementPackages: List<String> get() = Const.knownRootAppsPackages.toList()

    val dangerousPackages: List<String> get() = Const.knownDangerousAppsPackages.toList()

    val pathsThatShouldNotBeWritable: List<String> get() = Const.pathsThatShouldNotBeWritable.toList()

    /** Whether `RootBeerNative`'s static initialiser loaded `libtoolChecker.so`. */
    fun nativeLibraryLoaded(): Boolean = RootBeerNative().wasNativeLibraryLoaded()
}
