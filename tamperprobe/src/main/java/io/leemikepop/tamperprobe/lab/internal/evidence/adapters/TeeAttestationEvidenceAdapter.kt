package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.UnitPlan

/**
 * An attested boot state that agrees with the boot-state properties is published as a
 * concealable negative: an attestation forged for this app agrees with spoofed properties too.
 */
internal object TeeAttestationEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    plans = listOf(
        UnitPlan("tee-attestation.chain-and-root-of-trust", concealableNegativeKey = "concealableNegatives"),
    ),
)
