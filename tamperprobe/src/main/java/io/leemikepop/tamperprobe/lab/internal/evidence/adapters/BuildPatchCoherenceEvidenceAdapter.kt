package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.UnitPlan
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValue

internal object BuildPatchCoherenceEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "build-patch.security-patch-plausibility",
    plans = listOf(
        UnitPlan(
            "build-patch.security-patch-plausibility",
            setOf("comparablePartitionCount", "maximumSkewDays", "partitions", "findings"),
            signalMatcher = {
                it.hasArrayObjectValue(
                    "findings",
                    "unitId",
                    setOf("build-patch.security-patch-plausibility"),
                )
            },
        ),
    ),
)
