package io.leemikepop.tamperprobe.lab.lib.detections.appvisibility

/**
 * 靜態維護的危險包名與意圖清單
 */
internal object DangerousPackageList {
    val PACKAGES = listOf(
        // === Magisk & Kernel Su ===
        "com.topjohnwu.magisk",
        "io.github.vvb2060.magisk",
        "io.github.a13e300.ksuwebui",
        "me.weishu.kernelsu",
        "com.rifsxd.ksunext",
        "com.sukisu.ultra",
        // Observed installed on a Pixel 7 (2026-09-04) as leftover from a failed
        // Root-My-Pixel attempt; the manager ships an isolatedProcess + useAppZygote
        // service. Duck-Detector surfaced both of these where TamperProbe saw nothing.
        "com.resukisu.resukisu",
        "com.alex193a.rootmypixel",
        "top.canyie.magiskkiller",
        // From Duck-Detector's DangerousAppsCatalog ROOT_TOOL category (see the MISC block below).
        "me.bmax.apatch",
        "com.linux.permissionmanager", // SKRoot
        "com.rootmynothing.app",
        "dev.busung.s25uroot",

        // === LSPosed & Xposed ===
        "org.lsposed.manager",
        "org.lsposed.lspatch",
        "de.robv.android.xposed.installer",
        "me.weishu.exp",

        // === Hook 工具 ===
        "me.simpleHook",
        "top.hookvip.pro",
        "Hook.JiuWu.Xp",
        "com.bug.hookvip",
        "lin.xposed",
        "io.github.qauxv",
        "com.fkzhang.wechatxposed",
        "me.iacn.biliroaming",
        "com.padi.hook.hookqq",
        "top.sacz.timtool",
        "com.sevtinge.hyperceiler",
        "github.tornaco.android.thanos",
        "eu.faircode.xlua",

        // === 隱藏工具 ===
        "com.tsng.hidemyapplist",
        "com.tsng.pzyhrx.hma",
        "org.frknkrc44.hma_oss",
        "com.topmiaohan.hidebllist",
        "zako.zako.zako",

        // === App 修改/破解工具 ===
        "lucky.patcher",
        "com.chelpus.lackypatch",
        "com.android.vending.billing.InAppBillingService.LUCK",
        "ru.maximoff.apktool",
        "bin.mt.termex",
        "com.modify.installer",

        // === Root 管理器 (Legacy) ===
        "eu.chainfire.supersu",
        "com.noshufou.android.su",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",

        // === System Mod 工具 ===
        "com.omarea.vtools",
        "name.monwf.customiuizer",
        "com.coderstory.toolkit",
        "com.houvven.guise",
        "com.houvven.impad",
        "moe.shizuku.privileged.api",
        "moe.shizuku.redirectstorage",
        "me.gm.cleaner",

        // === Device ID 修改 ===
        "com.silverlab.app.deviceidchanger.free",

        // === Location 欺騙 ===
        "com.lerist.fakelocation",
        "com.zhufucyd.motion_emulator",

        // === 進程管理/凍結 ===
        "nep.timeline.freezer",
        "cn.myflv.noactive",
        "cn.myflv.monitor.noactive",
        "web1n.stopapp",
        "com.cshlolss.vipkill",

        // === 隱私/權限管理 ===
        "cn.geektang.privacyspace",
        "com.yuanwofei.cardemulator.pro",
        "com.suqi8.oshin",

        // === 系統修改相關 ===
        "tornaco.apps.shortx",
        "tornaco.apps.shortx.ext",
        "com.mio.kitchen",

        // === ROM 修改 ===
        "es.chiteroman.bootloaderspoofer",

        // === Terminal & Shell ===
        "com.termux",
        "com.termux.boot",
        "com.termux.api",
        "com.termux.widget",
        "jackpal.androidterm",
        "com.romide.terminal",
        "yarolegovich.materialterminal",

        // === 其他危險工具 ===
        "com.didjdk.adbhelper",
        "o.dyoo",
        "com.demo.serendipity",

        // === Duck-Detector MISC 類別 ===
        // Taken from Duck-Detector's DangerousAppsCatalog (Apache-2.0, eltavine/Duck-Detector-Refactoring
        // c149d30, 2026-10-08): its MISC category, mostly Xposed modules and system tweak tools.
        "me.bingyue.IceCore",
        "me.teble.xposed.autodaily",
        "moe.fuqiuluo.portal",
        "com.github.tianma8023.xposed.smscode",
        "xzr.hkf",
        "xzr.konabess",
        "com.xayah.databackup.foss",
        "com.byyoung.setting",
        "com.junge.algorithmAidePro",
        "tmgp.atlas.toolbox",
        "com.wn.app.np",
        "top.bienvenido.saas.i18n",
        "com.syyf.quickpay",
        "com.dna.tools",
        "me.hd.wauxv",
        "have.fun",
        "miko.client",
        "com.kooritea.fcmfix",
        "com.twifucker.hachidori",
        "com.luckyzyx.luckytool",
        "cn.lyric.getter",
        "com.parallelc.micts",
        "me.plusne",
        "com.hchen.appretention",
        "com.hchen.switchfreeform",
        "cn.aodlyric.xiaowine",
        "nep.timeline.re_telegram",
        "com.fuck.android.rimet",
        "cn.kwaiching.hook",
        "cn.android.x",
        "cc.aoeiuv020.iamnotdisabled.hook",
        "vn.kwaiching.tao",
        "com.nnnen.plusne",
        "one.yufz.hmspush",
        "cn.fuckhome.xiaowine",
        "com.fankes.tsbattery",
        "com.rkg.IAMRKG",
        "com.ddm.qute",
        "kk.dk.anqu",
        "com.qq.qcxm",
        "com.wei.vip",
        "dknb.con",
        "dknb.coo8",
        "com.tencent.jingshi",
        "com.tencent.JYNB",
        "com.apocalua.run",
        "io.github.Retmon403.oppotheme",
        "com.fankes.enforcehighrefreshrate",
        "com.hchai.rescueplan"
    )

    val KNOWN_INTENT_ACTIONS = mapOf(
        "com.topjohnwu.magisk" to listOf(
            "com.topjohnwu.magisk.REQUEST_INSTALL",
            "com.topjohnwu.magisk.SHOW",
        ),
        "io.github.a13e300.ksuwebui" to listOf(
            "io.github.a13e300.ksuwebui.LAUNCH",
        ),
        "org.lsposed.manager" to listOf(
            "org.lsposed.manager.SHOW",
        ),
        "de.robv.android.xposed.installer" to listOf(
            "de.robv.android.xposed.installer.SHOW",
        ),
    )
}
