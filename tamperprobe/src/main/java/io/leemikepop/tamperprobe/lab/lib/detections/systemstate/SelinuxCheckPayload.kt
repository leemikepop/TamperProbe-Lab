package io.leemikepop.tamperprobe.lab.lib.detections.systemstate

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import io.leemikepop.tamperprobe.lab.lib.detections.systemstate.shared.PropertyCollectionErrorPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class SelinuxCheckPayload(
    val filesystem: SelinuxFilesystemPayload = SelinuxFilesystemPayload(),
    val enforcementSources: List<SelinuxEnforcementSourcePayload> = emptyList(),
    val readDenialInference: SelinuxReadDenialInferencePayload = SelinuxReadDenialInferencePayload(),
    val writeProbe: SelinuxWriteProbePayload = SelinuxWriteProbePayload(),
    val processContext: SelinuxProcessContextPayload = SelinuxProcessContextPayload(),
    val findings: List<SelinuxFindingPayload> = emptyList(),
    val collectionErrors: List<PropertyCollectionErrorPayload> = emptyList(),
) : DetectionPayload

@Serializable
internal data class SelinuxFilesystemPayload(
    val path: String = "",
    val state: String = "unavailable",
    val fsType: Long? = null,
    val errno: Int? = null,
)

@Serializable
internal data class SelinuxEnforcementSourcePayload(
    val source: String = "",
    val state: String = "unavailable",
    val mode: String = "unknown",
    val error: String? = null,
    val errno: Int? = null,
)

/**
 * Telemetry for the selinuxfs_read_denial source: why an EACCES on reading the enforce node
 * was, or was not, taken as SELinux enforcing a denial on the app's own domain.
 */
@Serializable
internal data class SelinuxReadDenialInferencePayload(
    val state: String = "not_applicable",
    val readErrno: Int = 0,
    val readStep: String? = null,
    val reason: String? = null,
    val stat: SelinuxNodeStatPayload? = null,
    val dacBasis: String? = null,
    val dacPermitsRead: Boolean? = null,
    val kernelMode: String? = null,
    val anomaly: String? = null,
    val scope: String? = null,
)

@Serializable
internal data class SelinuxNodeStatPayload(
    val state: String = "unavailable",
    val mode: String? = null,
    val fileType: String? = null,
    val uid: Long? = null,
    val gid: Long? = null,
    val errno: Int? = null,
    val error: String? = null,
)

@Serializable
internal data class SelinuxWriteProbePayload(
    val path: String = "",
    val state: String = "unavailable",
    val writable: Boolean = false,
    val errno: Int? = null,
)

@Serializable
internal data class SelinuxProcessContextPayload(
    val path: String = "",
    val state: String = "unavailable",
    val context: String? = null,
    val domain: String? = null,
    val errno: Int? = null,
)

@Serializable
internal data class SelinuxFindingPayload(
    val id: String = "",
    val strength: String = "",
    val summary: String = "",
    val detail: String = "",
)
