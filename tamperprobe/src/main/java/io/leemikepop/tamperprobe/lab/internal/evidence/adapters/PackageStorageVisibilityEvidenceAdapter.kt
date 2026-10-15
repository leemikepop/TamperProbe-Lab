package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.UnitPlan
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValue

internal object PackageStorageVisibilityEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "package-storage.path-visibility",
    plans = listOf(
        UnitPlan(
            "package-storage.path-visibility",
            setOf("overview", "packageObservations", "findings"),
            signalMatcher = {
                it.hasArrayObjectValue("findings", "id", setOf("canonical_package_data", "unicode_alias"))
            },
        ),
        UnitPlan(
            "package-storage.path-representation-differential",
            setOf("storageContext", "packageObservations", "telemetry"),
            researchOnly = true,
        ),
    ),
)
