package io.leemikepop.tamperprobe.lab.internal

import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.TamperProbeException
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

@Serializable
internal data class WireEnvelope(
    val schemaVersion: Int = 0,
    val engineVersion: String = "",
    val catalogVersion: String = "",
    val completion: String = "FAILED",
    // Time spent inside the native scan, excluding the JNI hop and everything the
    // Kotlin side does around it. The client's own durationMillis measures the wider
    // span; the difference between the two is SDK overhead.
    val durationMicros: Long = 0,
    val results: List<WireDetectorResult> = emptyList(),
    val engineError: WireEngineError? = null,
)

@Serializable
internal data class WireDetectorResult(
    val detectorId: String,
    val outcome: DetectionOutcome,
    val evidenceStrength: EvidenceStrength,
    // Wall time of this detector's execute() alone. The parser rejects unknown keys, so
    // this field and the native envelope that emits it must ship together.
    val durationMicros: Long = 0,
    val payload: JsonObject = JsonObject(emptyMap()),
    val collectionError: String? = null,
)

@Serializable
internal data class WireEngineError(
    val code: String,
    val message: String,
)

internal object WireParser {
    private val json = Json { ignoreUnknownKeys = false }

    fun parse(bytes: ByteArray): WireEnvelope {
        if (bytes.isEmpty()) {
            throw TamperProbeException("EMPTY_WIRE_RESPONSE", "Native engine returned no data")
        }
        val envelope = try {
            json.decodeFromString<WireEnvelope>(bytes.toString(Charsets.UTF_8))
        } catch (error: Exception) {
            throw TamperProbeException("WIRE_DECODE_FAILED", "Unable to decode native scan response", error)
        }
        if (envelope.schemaVersion != 1) {
            throw TamperProbeException(
                "UNSUPPORTED_WIRE_SCHEMA",
                "Unsupported native wire schema: ${envelope.schemaVersion}",
            )
        }
        return envelope
    }
}
