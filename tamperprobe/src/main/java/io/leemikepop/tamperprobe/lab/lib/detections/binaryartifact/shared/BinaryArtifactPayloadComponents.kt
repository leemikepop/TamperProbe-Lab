package io.leemikepop.tamperprobe.lab.lib.detections.binaryartifact.shared

import kotlinx.serialization.Serializable

@Serializable
internal data class BinaryArtifactOverview(
    val candidateCount: Int = 0,
    val environmentCandidateCount: Int = 0,
    val availableCandidateCount: Int = 0,
    val unavailableCandidateCount: Int = 0,
    val findingCount: Int = 0,
    val strongFindingCount: Int = 0,
    val weakFindingCount: Int = 0,
    val deniedOperationCount: Int = 0,
    val errorOperationCount: Int = 0,
)

@Serializable
internal data class BinaryArtifactOperation(
    val state: String = "not_attempted",
    val errno: Int = 0,
    val fileType: String? = null,
    val mode: Int? = null,
    val uid: Int? = null,
    val gid: Int? = null,
    val size: Long? = null,
    val device: Long? = null,
    val inode: Long? = null,
    val format: String? = null,
    val bytesRead: Long? = null,
    val sameResolvedObject: Boolean? = null,
)

@Serializable
internal data class BinaryArtifactProbe(
    val path: String,
    val candidateSource: String = "fixed_path",
    val access: BinaryArtifactOperation = BinaryArtifactOperation(),
    val lstat: BinaryArtifactOperation = BinaryArtifactOperation(),
    val openPath: BinaryArtifactOperation = BinaryArtifactOperation(),
    val fstat: BinaryArtifactOperation = BinaryArtifactOperation(),
    val header: BinaryArtifactOperation = BinaryArtifactOperation(),
)

@Serializable
internal data class BinaryArtifactFinding(
    val id: String,
    val path: String,
    val candidateSource: String = "fixed_path",
    val strength: String,
    val classification: String,
    val summary: String,
)
