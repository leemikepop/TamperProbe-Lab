package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.UnitPlan
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValue

internal object PropertyAreaResidueEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "system-property-residue.serial-anomaly",
    plans = listOf(
        UnitPlan(
            "system-property-residue.serial-anomaly",
            setOf("parsedAreaCount", "totalPropertiesInspected", "serialAnomalyCount", "findings"),
            signalMatcher = {
                it.hasArrayObjectValue(
                    "findings",
                    "unitId",
                    setOf("system-property-residue.serial-anomaly"),
                ) || it.hasArrayObjectValue(
                    "findings",
                    "anomalyType",
                    setOf("LENGTH_MISMATCH", "RO_SERIAL_MODIFIED"),
                )
            },
        ),
        UnitPlan(
            "system-property-residue.trailing-bytes",
            // readOnly/writableTrailingResidueCount split the total by whether the property was
            // read-only, which is what distinguishes a security-relevant residue from an
            // ordinary one. Native emitted both from the start; neither was declared here, so
            // both were filtered out of the unit report.
            setOf(
                "parsedAreaCount",
                "totalPropertiesInspected",
                "trailingResidueCount",
                "readOnlyTrailingResidueCount",
                "writableTrailingResidueCount",
                "findings",
            ),
            signalMatcher = {
                it.hasArrayObjectValue(
                    "findings",
                    "unitId",
                    setOf("system-property-residue.trailing-bytes"),
                ) || it.hasArrayObjectValue(
                    "findings",
                    "anomalyType",
                    setOf("TRAILING_BYTES"),
                )
            },
        ),
    ),
)
