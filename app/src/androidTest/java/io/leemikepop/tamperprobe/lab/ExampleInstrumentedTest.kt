package io.leemikepop.tamperprobe.lab

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.ScanRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented test, which will execute on an Android device.
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
@RunWith(AndroidJUnit4::class)
class ExampleInstrumentedTest {
    @Test
    fun useAppContext() {
        // Context of the app under test.
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("io.leemikepop.tamperprobe.lab", appContext.packageName)
    }

    @Test
    fun lsposedSepolicyUsesAppZygoteCarrierAcrossRepeatedScans() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val client = TamperProbe.create(context)
        val cjk = Regex("[\\u3400-\\u9fff]")

        repeat(2) { scanIndex ->
            val result = client.scanBlocking(
                ScanRequest(setOf("LSPOSED_SEPOLICY")),
            ).results.single()
            val records = result.unitResults.flatMap { it.records }
            val carrier = records.firstOrNull {
                it.attributes["carrier.state"] == "present" &&
                    it.attributes.containsKey("carrier.domain")
            }

            assertTrue(result.outcome != DetectionOutcome.FAILED)
            assertTrue(!cjk.containsMatchIn(result.descriptor.name))
            assertTrue(!cjk.containsMatchIn(result.descriptor.description))
            assertTrue(records.none { cjk.containsMatchIn(it.summary) })
            assertNotNull("Missing app-zygote carrier evidence", carrier)
            assertEquals("app_zygote", carrier?.attributes?.get("carrier.domain"))
            assertEquals("true", carrier?.attributes?.get("carrier.uidMatches"))
            Log.i(
                "TamperProbeAppZygoteTest",
                    "scan=$scanIndex outcome=${result.outcome} " +
                    "carrierDomain=${carrier?.attributes?.get("carrier.domain")} " +
                    "uidMatches=${carrier?.attributes?.get("carrier.uidMatches")} " +
                    "records=${records.map { evidence ->
                        mapOf(
                            "code" to evidence.code,
                            "attributes" to evidence.attributes,
                        )
                    }}",
            )
        }
    }
}
