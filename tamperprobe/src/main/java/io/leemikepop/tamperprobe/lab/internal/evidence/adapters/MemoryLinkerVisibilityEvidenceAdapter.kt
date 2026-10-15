package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.UnitPlan

internal object MemoryLinkerVisibilityEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    plans = listOf(
        UnitPlan(
            "memory-linker.module-view-consistency",
            payloadKeys = setOf(
                "linkerOnlyModules",
                "mapsOnlyModules",
                "gotPltEscapes",
                "linkerObjectCount",
                "findingCount",
                "scannedMappings",
                "mapsReadable",
                "malformedMapLines",
            ),
            // These must match the keys the native payload actually writes. They previously
            // read linkerOnly / mapsOnly / missingOptionalLibraries, none of which the C++
            // ever emitted, so the research snapshot for this unit was always empty.
            researchKeys = setOf("linkerOnlyModules", "mapsOnlyModules"),
        ),
    ),
)
