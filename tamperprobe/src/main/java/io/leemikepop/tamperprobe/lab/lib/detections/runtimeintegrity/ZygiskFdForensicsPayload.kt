package io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class ZygiskFdForensicsPayload(
    val overview: FdForensicsOverviewPayload = FdForensicsOverviewPayload(),
    val hostProcess: FdForensicsTablePayload = FdForensicsTablePayload(),
    val carrierProcess: FdForensicsCarrierPayload = FdForensicsCarrierPayload(),
    val trapChannel: FdForensicsTrapChannelPayload = FdForensicsTrapChannelPayload(),
    val findings: List<FdForensicsFindingPayload> = emptyList(),
    val collectionErrors: List<FdForensicsCollectionErrorPayload> = emptyList(),
    val collectionStatus: String = "",
) : DetectionPayload

@Serializable
internal data class FdForensicsOverviewPayload(
    val hostConfirmedCount: Int = 0,
    val carrierConfirmedCount: Int = 0,
    val findingCount: Int = 0,
    val carrierAvailable: Boolean = false,
    val hostViewsUsable: Boolean = false,
    val carrierViewsUsable: Boolean = false,
    val processDivergence: Boolean = false,
)

@Serializable
internal data class FdForensicsTablePayload(
    val scannedDescriptorRange: Int = 0,
    val iterateViewReadable: Boolean = false,
    val tableOpenCount: Int = 0,
    val lookupOpenCount: Int = 0,
    val candidateCount: Int = 0,
    val unstableCandidateCount: Int = 0,
    val procfsUnusable: Boolean = false,
    val hiddenFromIterateCount: Int = 0,
    val hiddenFromLookupCount: Int = 0,
    val phantomCount: Int = 0,
    val confirmedCount: Int = 0,
    val contradictions: List<FdForensicsContradictionPayload> = emptyList(),
    val collectionError: String = "",
)

@Serializable
internal data class FdForensicsContradictionPayload(
    val descriptor: Int = -1,
    val tableOpen: Boolean = false,
    val lookupOpen: Boolean = false,
    val iterateOpen: Boolean = false,
    val category: String = "",
    val targetClass: String = "",
)

@Serializable
internal data class FdForensicsCarrierPayload(
    val available: Boolean = false,
    val descriptorTable: FdForensicsTablePayload = FdForensicsTablePayload(),
    val trapDescriptor: FdForensicsTrapDescriptorPayload = FdForensicsTrapDescriptorPayload(),
    val collectionError: String = "",
)

@Serializable
internal data class FdForensicsTrapDescriptorPayload(
    val status: String = "",
    val targetClass: String = "",
    val bytesRead: Int = 0,
    val errorCode: Int = 0,
)

@Serializable
internal data class FdForensicsTrapChannelPayload(
    val carrierStatus: String = "",
    val assessmentImpact: String = "",
)

@Serializable
internal data class FdForensicsFindingPayload(
    val id: String = "",
    val unitId: String = "",
    val process: String = "",
    val category: String = "",
    val descriptor: Int = -1,
    val targetClass: String = "",
    val strength: String = "",
    val summary: String = "",
    val detail: String = "",
)

@Serializable
internal data class FdForensicsCollectionErrorPayload(
    val source: String = "",
    val message: String = "",
)
