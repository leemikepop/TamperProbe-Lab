package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.UnitPlan
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValue

internal object DrmCredentialCoherenceEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "drm-credential.boot-state-coherence",
    plans = listOf(
        UnitPlan(
            "drm-credential.boot-state-coherence",
            setOf("schemeSupported", "securityLevel", "systemIdState", "comparable", "bootClaim", "findings"),
            signalMatcher = {
                it.hasArrayObjectValue(
                    "findings",
                    "unitId",
                    setOf("drm-credential.boot-state-coherence"),
                )
            },
        ),
    ),
)
