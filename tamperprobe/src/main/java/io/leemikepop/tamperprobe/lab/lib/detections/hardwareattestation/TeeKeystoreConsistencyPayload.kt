package io.leemikepop.tamperprobe.lab.lib.detections.hardwareattestation

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
internal data class TeeKeystoreConsistencyPayload(
    val checks: List<KeystoreConsistencyCheckPayload> = emptyList(),
    val findings: List<TeeAttestationFindingPayload> = emptyList(),
    val collectionWarnings: List<TeeCollectionWarningPayload> = emptyList(),
    val requiredCheckCount: Int = 0,
    val completedRequiredCheckCount: Int = 0,
    val requiredContradictionCount: Int = 0,
    val collectionError: String? = null,
) : DetectionPayload

@Serializable
internal data class KeystoreConsistencyCheckPayload(
    val id: String = "",
    val required: Boolean = false,
    val state: String = "unavailable",
    val detail: JsonObject = JsonObject(emptyMap()),
)
