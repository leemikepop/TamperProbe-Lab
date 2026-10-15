package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.IssueRoute
import io.leemikepop.tamperprobe.lab.internal.UnitPlan
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValue

internal object SystemPropertiesTamperEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "system-properties.source-consistency",
    plans = listOf(
        UnitPlan(
            unitId = "system-properties.source-consistency",
            payloadKeys = setOf("overview", "findings", "comparisons", "sources"),
            signalMatcher = { payload ->
                payload.hasArrayObjectValue(
                    "findings",
                    "id",
                    setOf(
                        "property_source_mismatch",
                        "property_accessor_contradiction",
                        "property_snapshot_drift",
                        "boot_property_inconsistency",
                    ),
                )
            },
            // A source that could not read a compared property carries that property's name;
            // the comparisons run over securityPropertyKeys(). A property area that failed to
            // parse carries none and stays shared, because it also withdraws the raw-byte
            // property_area:<context> source from these comparisons.
            issueRoutes = listOf(
                IssueRoute(
                    "property",
                    setOf(
                        "ro.secure",
                        "ro.debuggable",
                        "ro.build.type",
                        "ro.build.tags",
                        "ro.boot.verifiedbootstate",
                        "ro.boot.flash.locked",
                        "ro.boot.vbmeta.device_state",
                        "service.adb.root",
                    ),
                ),
            ),
        ),
        UnitPlan(
            unitId = "system-properties.area-layout",
            payloadKeys = setOf("areaSummary", "propertyAreas", "findings"),
            signalMatcher = { payload ->
                payload.hasArrayObjectValue(
                    "findings",
                    "id",
                    setOf("prop_area_unreferenced_hole"),
                )
            },
        ),
    ),
)
