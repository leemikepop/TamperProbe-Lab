package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.UnitPlan

/**
 * A rule whose target type is absent supports NOT_OBSERVED only as a concealable negative
 * (KernelSU's Hide SELinux modification removes ksu_file), so each one is published as its own record.
 */
internal object NativeRootSepolicyEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    plans = listOf(
        UnitPlan("native-root-sepolicy.policy-oracle", concealableNegativeKey = "concealableNegatives"),
    ),
)
