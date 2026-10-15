package io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity.shared.HookCollectionErrorPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class VdsoIntegrityPayload(
    val findings: List<VdsoFindingPayload> = emptyList(),
    val collectionErrors: List<HookCollectionErrorPayload> = emptyList(),
    val mapsReadable: Boolean = false,
    val malformedMapLines: Int = 0,
    val mappingCount: Int = 0,
    val mappingStart: Long = 0,
    val mappingEnd: Long = 0,
    val mappingPermissions: String = "",
    val auxvAddress: Long = 0,
    val auxvMatchesMapping: Boolean = false,
    val elfHeaderValid: Boolean = false,
    val loadSegmentsValid: Boolean = false,
    val linkerOwnerFound: Boolean = false,
    val linkerOwnerPath: String = "",
    val symbolCheckAvailable: Boolean = false,
    val checkedSymbol: String = "",
    val resolvedSymbolAddress: Long = 0,
    val symbolOwnedByVdso: Boolean = false,
    val findingCount: Int = 0,
) : DetectionPayload

@Serializable
internal data class VdsoFindingPayload(
    val type: String = "",
    val detail: String = "",
    val assessmentImpact: String = "",
)
