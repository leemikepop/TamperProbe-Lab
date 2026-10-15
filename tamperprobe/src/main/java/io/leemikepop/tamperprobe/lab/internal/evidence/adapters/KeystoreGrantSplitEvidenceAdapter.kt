package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.UnitPlan
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValue

internal object KeystoreGrantSplitEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "keystore-grant.chain-consistency",
    plans = listOf(
        UnitPlan(
            "keystore-grant.chain-consistency",
            setOf(
                "available",
                "apiLevel",
                "grantIssued",
                "grantReadback",
                "controlReadback",
                "split",
                "splitKind",
                "ownerChain",
                "granteeChain",
                "findings",
            ),
            signalMatcher = {
                it.hasArrayObjectValue(
                    "findings",
                    "unitId",
                    setOf("keystore-grant.chain-consistency"),
                )
            },
        ),
    ),
)
