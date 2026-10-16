package io.leemikepop.tamperprobe.lab.retrofit.rootbeer

import android.app.Activity
import android.content.Context
import android.os.Bundle
import io.leemikepop.tamperprobe.lab.retrofit.common.HostProvenance
import io.leemikepop.tamperprobe.lab.retrofit.common.RetrofitRun
import io.leemikepop.tamperprobe.lab.retrofit.common.RetrofitText
import java.time.Instant

/** Runs the retrofit on launch and shows each check's upstream verdict next to its contract outcome. */
class RootBeerRetrofitActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        RetrofitText.showRun(this) { runRootBeerRetrofit(applicationContext) }
    }
}

/** One full run: every check, then `isRooted()` as an integrator would call it. */
fun runRootBeerRetrofit(context: Context): RetrofitRun {
    val retrofit = RootBeerRetrofit(context)
    val startedAtUtc = Instant.now()
    val evaluations = retrofit.evaluate()
    val aggregate = retrofit.aggregateVerdict()
    return RetrofitRun(
        selection = "rootbeer",
        upstream = RootBeerRetrofit.UPSTREAM,
        aggregateVerdict = aggregate,
        startedAtUtc = startedAtUtc,
        completedAtUtc = Instant.now(),
        evaluations = evaluations,
        host = HostProvenance(
            applicationId = context.packageName,
            versionName = BuildConfig.VERSION_NAME,
            versionCode = BuildConfig.VERSION_CODE,
            gitCommit = BuildConfig.GIT_COMMIT,
            gitDirty = BuildConfig.GIT_DIRTY,
            buildType = BuildConfig.BUILD_TYPE,
            targetSdk = context.applicationInfo.targetSdkVersion,
            packageVisibility = retrofit.packageVisibility,
        ),
    )
}
