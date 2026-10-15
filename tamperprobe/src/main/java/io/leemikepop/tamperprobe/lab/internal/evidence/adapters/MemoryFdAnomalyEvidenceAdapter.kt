package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.UnitPlan

internal object MemoryFdAnomalyEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    plans = listOf(
        UnitPlan(
            "memory-fd.executable-artifact",
            // "telemetry" was declared but never emitted by the collector. candidates is
            // research material and is carried only by the research snapshot.
            researchKeys = setOf("candidates"),
        ),
    ),
)
