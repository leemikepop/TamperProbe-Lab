package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.IssueRoute
import io.leemikepop.tamperprobe.lab.internal.UnitPlan
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValue

internal object SelinuxCheckEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "selinux.enforcement-state",
    plans = listOf(
        UnitPlan(
            "selinux.enforcement-state",
            setOf("enforcementSources", "readDenialInference", "processContext", "findings"),
            signalMatcher = {
                it.hasArrayObjectValue("findings", "id", setOf("selinux_disabled", "selinux_permissive"))
            },
            // The unit's proposition is "one or more sources report a mode", so one answered
            // source (a read, or selinuxfs_read_denial) completes it. Native raises
            // enforcement_sources only when no source answered; a single failed source is a
            // gap for the cross-source unit alone.
            issueRoutes = listOf(
                IssueRoute("source", setOf("enforcement_sources", "process_context")),
            ),
        ),
        UnitPlan(
            "selinux.enforce-node-access",
            setOf("filesystem", "writeProbe", "readDenialInference"),
            signalMatcher = {
                it.hasArrayObjectValue("findings", "id", setOf("enforce_node_writable"))
            },
            issueRoutes = listOf(IssueRoute("source", setOf("selinuxfs", "write_probe"))),
        ),
        UnitPlan(
            "selinux.cross-source-consistency",
            setOf("enforcementSources", "readDenialInference", "filesystem", "writeProbe", "findings"),
            signalMatcher = {
                it.hasArrayObjectValue(
                    "findings",
                    "id",
                    setOf("enforcement_source_contradiction", "inferred_enforcement_contradiction"),
                )
            },
            // process_context feeds only the enforcement-state unit; every other source is
            // one of the views this unit compares.
            issueRoutes = listOf(
                IssueRoute(
                    "source",
                    setOf("selinuxfs", "selinuxfs_enforce", "libselinux", "write_probe", "enforcement_sources"),
                ),
            ),
        ),
    ),
)
