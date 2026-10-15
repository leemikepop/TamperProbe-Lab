package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.UnitPlan

internal object PrologueScannerEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "prologue-scanner.entry-integrity",
    plans = listOf(
        UnitPlan("prologue-scanner.entry-integrity", setOf("checks", "findings")),
        // These keys must exist in the payload. The plan previously named "patterns" and
        // "telemetry", and the detector emitted neither, so this unit published a RESEARCH
        // record with no attributes on every device - declared, reported, and empty.
        UnitPlan(
            "prologue-scanner.entry-pattern",
            setOf(
                "patterns",
                "entryPatternPolicy",
                "entryPatternArchitecture",
                "patternObservationCount",
                "branchLikeFunctionCount",
                "trampolineFunctionCount",
            ),
            researchOnly = true,
        ),
    ),
)
