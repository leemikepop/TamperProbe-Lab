package io.leemikepop.tamperprobe.lab.retrofit.ruru

import android.app.Activity
import android.content.Context
import android.os.Bundle
import io.leemikepop.tamperprobe.lab.retrofit.common.HostProvenance
import io.leemikepop.tamperprobe.lab.retrofit.common.RetrofitRun
import io.leemikepop.tamperprobe.lab.retrofit.common.RetrofitText
import java.time.Instant

/** Runs the retrofit on launch and shows each check's upstream verdict next to its contract outcome. */
class RuruRetrofitActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        RetrofitText.showRun(this) { runRuruRetrofit(applicationContext) }
    }
}

/** One full run of the ten library checks, in the order Ruru's main page runs them. */
fun runRuruRetrofit(context: Context): RetrofitRun {
    val retrofit = RuruRetrofit(context)
    val startedAtUtc = Instant.now()
    val evaluations = retrofit.evaluate()
    return RetrofitRun(
        selection = "ruru",
        upstream = RuruRetrofit.UPSTREAM,
        aggregateVerdict = retrofit.aggregateVerdict(evaluations),
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
