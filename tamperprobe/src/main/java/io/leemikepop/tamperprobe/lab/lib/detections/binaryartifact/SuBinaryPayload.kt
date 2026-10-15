package io.leemikepop.tamperprobe.lab.lib.detections.binaryartifact

import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import io.leemikepop.tamperprobe.lab.lib.detections.binaryartifact.shared.BinaryArtifactFinding
import io.leemikepop.tamperprobe.lab.lib.detections.binaryartifact.shared.BinaryArtifactOverview
import io.leemikepop.tamperprobe.lab.lib.detections.binaryartifact.shared.BinaryArtifactProbe
import kotlinx.serialization.Serializable

@Serializable
internal data class SuBinaryPayload(
    val overview: BinaryArtifactOverview = BinaryArtifactOverview(),
    val foundPaths: List<String> = emptyList(),
    val findings: List<BinaryArtifactFinding> = emptyList(),
    val probes: List<BinaryArtifactProbe> = emptyList(),
) : DetectionPayload
