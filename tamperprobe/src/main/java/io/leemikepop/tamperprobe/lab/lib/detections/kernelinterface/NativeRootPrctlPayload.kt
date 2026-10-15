package io.leemikepop.tamperprobe.lab.lib.detections.kernelinterface

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class NativeRootPrctlPayload(
    val findings: List<NativeRootPrctlFindingPayload> = emptyList(),
    val ksuDetected: Boolean = false,
    val ksuVersion: Long = 0,
    val supercallTested: Boolean = false,
    val supercallLatencyDiffUs: Double = 0.0,
    val apatchDetected: Boolean = false,
    val cgroupChecked: Boolean = false,
    val cgroupAnomaly: Boolean = false,
    val driverFdCount: Int = 0,
    val fdwrapperCount: Int = 0,
    val selfSelinuxContext: String = "",
    val hitCount: Int = 0,
) : DetectionPayload

@Serializable
internal data class NativeRootPrctlFindingPayload(
    val check: String = "",
    val probe: String = "",
    val result: String = "",
    val severity: String = "",
    val value: String = "",
    val detail: String? = null,
)
