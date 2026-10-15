package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.IssueRoute
import io.leemikepop.tamperprobe.lab.internal.UnitPlan
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValue

internal object ZygiskFdForensicsEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "zygisk-fd-forensics.descriptor-view-differential",
    plans = listOf(
        UnitPlan(
            "zygisk-fd-forensics.descriptor-view-differential",
            setOf("overview", "hostProcess", "carrierProcess", "findings"),
            signalMatcher = {
                it.hasArrayObjectValue(
                    "findings",
                    "id",
                    setOf("descriptor_hidden_from_iterate", "descriptor_hidden_from_lookup"),
                ) || it.hasArrayObjectValue(
                    "findings",
                    "unitId",
                    setOf("zygisk-fd-forensics.descriptor-view-differential"),
                )
            },
            // The host table feeds only this unit. carrier_process stays unrouted and shared:
            // an unavailable carrier also takes the trap descriptor with it, and native reports
            // a failed carrier table under the same source.
            issueRoutes = listOf(IssueRoute("source", setOf("host_process"))),
        ),
        // The trap channel is telemetry only: the descriptor is installed into the
        // carrier process by the binder driver after that process has finished
        // specializing, so no outcome of this channel supports a tamper claim.
        UnitPlan(
            "zygisk-fd-forensics.cross-process-trap",
            setOf("trapChannel"),
            signalMatcher = { false },
        ),
    ),
)
