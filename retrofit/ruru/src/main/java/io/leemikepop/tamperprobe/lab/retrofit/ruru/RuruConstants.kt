package io.leemikepop.tamperprobe.lab.retrofit.ruru

/**
 * Targets copied from Ruru 30694c2 so the shadow probes ask about exactly what upstream asks about.
 * Ruru is Apache-2.0; see retrofit/NOTICE.md.
 */
internal object RuruConstants {
    /** `basicAppList` in app/src/main/java/icu/nullptr/applistdetector/MainPage.kt. */
    val BASIC_APP_LIST: List<String> = listOf(
        "com.topjohnwu.magisk",
        "io.github.vvb2060.magisk",
        "io.github.vvb2060.magisk.lite",
        "de.robv.android.xposed.installer",
        "org.meowcat.edxposed.manager",
        "org.lsposed.manager",
        "top.canyie.dreamland.manager",
        "me.weishu.exp",
        "com.tsng.hidemyapplist",
        "cn.geektang.privacyspace",
        "moe.shizuku.redirectstorage",
    )

    /** The marker files AbnormalEnvironment checks, by the item name it reports them under. */
    val MARKER_FILES: Map<String, List<String>> = linkedMapOf(
        "HMA (old version)" to listOf("/data/misc/hide_my_applist"),
        "XPrivacyLua" to listOf("/data/system/xlua"),
        "TWRP" to listOf("/storage/emulated/0/TWRP", "/storage/emulated/TWRP"),
        "Xposed Edge" to listOf("/data/system/xedge"),
        "Riru Clipboard" to listOf("/data/misc/clipboard"),
        "privacyspace" to listOf("/data/system/cn.geektang.privacyspace"),
    )

    /** AbnormalEnvironment's item names for the root binaries, and the file name each counts. */
    val ROOT_BINARY_ITEMS: Map<String, String> = linkedMapOf(
        "Su File" to "su",
        "Busybox File" to "busybox",
        "Magisk File" to "magisk",
    )

    /** AbnormalEnvironment's `places`, verbatim: "/cache" has no trailing slash upstream. */
    val ROOT_BINARY_PLACES: List<String> = listOf(
        "/sbin/", "/system/bin/", "/system/xbin/", "/proc/self/root/bin/", "/data/local/xbin/",
        "/data/local/bin/", "/system/sd/xbin/", "/system/bin/failsafe/", "/data/local/", "/cache",
    )

    /** FileDetection's six paths per package, as format strings. */
    val DATA_PATH_FAMILIES: List<String> = listOf(
        "/data/data/%s",
        "/data/user_de/0/%s",
        "/data/misc/profiles/ref/%s",
        "/storage/emulated/0/Android/data/%s",
        "/storage/emulated/0/Android/media/%s",
        "/storage/emulated/0/Android/obb/%s",
    )
}
