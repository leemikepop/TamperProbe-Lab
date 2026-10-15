package io.leemikepop.tamperprobe.lab.lib.detections.appvisibility

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import kotlinx.serialization.Serializable

@Serializable
internal data class UnitCollectionIssuePayload(
    val code: String,
    val message: String,
    val attributes: Map<String, String>,
)

@Serializable
internal data class PackageIdentityPayload(
    val targetCount: Int,
    val completedQueryCount: Int,
    val visiblePackageCount: Int = -1,
    val detectedPackages: List<String>,
    val issues: List<UnitCollectionIssuePayload>,
)

@Serializable
internal data class AppDataPathPayload(
    val attemptedPathCount: Int,
    val completedPathCount: Int,
    val notFoundPathCount: Int,
    val foundPaths: List<String>,
    val inaccessiblePaths: List<String>,
    val issues: List<UnitCollectionIssuePayload>,
    val unconfirmedNotFoundCount: Int = 0,
    val selfControl: String = "not_attempted",
    val crossPackageControl: String = "not_attempted",
    val isolationDetected: Boolean = false,
)

@Serializable
internal data class DangerousPackagesPayload(
    val packageIdentity: PackageIdentityPayload,
    val appDataPath: AppDataPathPayload,
) : DetectionPayload
