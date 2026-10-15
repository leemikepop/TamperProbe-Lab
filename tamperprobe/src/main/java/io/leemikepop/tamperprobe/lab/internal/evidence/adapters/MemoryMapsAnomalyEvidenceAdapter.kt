package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.UnitPlan

internal object MemoryMapsAnomalyEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    plans = listOf(
        UnitPlan(
            "memory-maps.executable-mapping-anomaly",
            payloadKeys = setOf(
                "findings",
                "findingCount",
                "assessmentBearingFindingCount",
                "scannedMappings",
                "mapsReadable",
                "smapsReadable",
                "malformedMapLines",
            ),
        ),
    ),
)
