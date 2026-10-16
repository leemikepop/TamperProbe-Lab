package io.leemikepop.tamperprobe.lab.retrofit.ruru

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.leemikepop.tamperprobe.lab.retrofit.common.InstrumentationShellWriter
import io.leemikepop.tamperprobe.lab.retrofit.common.RetrofitExport
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Captures one Ruru retrofit run as an export document in `/data/local/tmp`.
 *
 *     gradlew :retrofit:ruru:connectedDebugAndroidTest \
 *       -Pandroid.injected.androidTest.leaveApksInstalledAfterRun=true
 *     adb -s <serial> pull /data/local/tmp/<name>
 *
 * Keep the host installed between runs: concealment modules are configured against the installed
 * package. The path is logged under tag `RetrofitExport`.
 */
@RunWith(AndroidJUnit4::class)
class RuruRetrofitExportTest {
    @Test
    fun capturesOneRunAsAnExportDocument() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val run = runRuruRetrofit(instrumentation.targetContext)
        assertEquals(RuruSpecs.ALL.size, run.results.size)

        val document = RetrofitExport.createDocument(run, Instant.now())
        val target = "/data/local/tmp/${document.fileName}"
        val written = InstrumentationShellWriter.write(instrumentation.uiAutomation, target, document.bytes)
        assertEquals(document.bytes.size.toLong(), written)
        Log.i(
            "RetrofitExport",
            "export_written path=$target highest=${run.aggregateVerdict} " +
                "outcomes=${run.results.joinToString(",") { "${it.descriptor.id}:${it.outcome}" }}",
        )
    }
}
