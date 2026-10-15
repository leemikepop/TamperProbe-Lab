package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.IssueRoute
import io.leemikepop.tamperprobe.lab.internal.UnitPlan
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValue
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValueOutside

/**
 * Every unit here carries `mountInfoReadable` and `mountInfoEntryCount`, because all three
 * viewpoints are built on the same parsed mount table: if it was unreadable or empty, none
 * of them observed anything, and a consumer cannot tell that from the records alone. The
 * detector-wide finding tallies sit on the signal unit, and the statx/statfs coverage sits
 * on the unit that performs those calls.
 *
 * These nine keys were emitted by the C++ and deserialized by [MountIntegrityPayload] but
 * declared by no `UnitPlan`, so `selectAttributes` filtered them out and they reached no
 * report on any device — verified absent across all fourteen cells of `ablation_2026`.
 * That made `NOT_OBSERVED` unfalsifiable here: the report asserted nothing was found while
 * withholding whether the mount table had been read at all.
 */
internal object MountIntegrityEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "mount-integrity.table-marker",
    plans = listOf(
        UnitPlan(
            "mount-integrity.table-marker",
            setOf(
                "findings",
                "directBlockMounts",
                "genericMountHeuristics",
                "mountInfoReadable",
                "mountInfoEntryCount",
                "findingCount",
                "strongFindingCount",
                "moderateFindingCount",
                "weakFindingCount",
            ),
            signalMatcher = {
                it.hasArrayObjectValueOutside(
                    "findings",
                    "id",
                    setOf(
                        "statx_mount_id_missing",
                        "hidden_overlayfs",
                        "shared_init_namespace",
                    ),
                )
            },
        ),
        UnitPlan(
            "mount-integrity.kernel-view-consistency",
            setOf(
                "statxChecks",
                "statfsChecks",
                "hiddenMountIdCount",
                "hiddenOverlayCount",
                "mountInfoReadable",
                "mountInfoEntryCount",
                "overlayDeclared",
                "completedStatxChecks",
                "completedStatfsChecks",
            ),
            signalMatcher = {
                it.hasArrayObjectValue(
                    "findings",
                    "id",
                    setOf("statx_mount_id_missing", "hidden_overlayfs"),
                )
            },
            // statx backs only this unit's mount-ID cross-check. An unreadable mountinfo is
            // left unrouted: all three units are built on that table, so it stays shared.
            issueRoutes = listOf(IssueRoute("source", setOf("statx"))),
        ),
        UnitPlan(
            "mount-integrity.namespace-observation",
            setOf(
                "mountIdSequence",
                "selfNamespace",
                "initNamespace",
                "sharesInitNamespace",
                "rootPropagationPrivate",
                "mountInfoReadable",
                "mountInfoEntryCount",
            ),
            signalMatcher = {
                it.hasArrayObjectValue(
                    "findings",
                    "id",
                    setOf("shared_init_namespace"),
                )
            },
        ),
    ),
)
