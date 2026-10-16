package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.IssueRoute
import io.leemikepop.tamperprobe.lab.internal.UnitPlan
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValue
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValueOutside
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

private const val IDENTITY_MISMATCH_CHECK = "kernel_identity_mismatch"

/**
 * Two units. The integrity posture keeps every pre-existing payload field and signals on any
 * finding other than an identity mismatch. The identity coherence unit signals only on a
 * release disagreement, reads UNAVAILABLE when fewer than two release sources were readable,
 * and on NOT_OBSERVED publishes its agreement as a concealable negative. A banner scan that saw
 * only the uname syscall publishes its not-found the same way.
 */
internal object KernelCheckEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "kernel-check.integrity-posture",
    plans = listOf(
        UnitPlan(
            "kernel-check.integrity-posture",
            setOf(
                "kernelRelease",
                "kernelVersion",
                "procVersion",
                "procCmdline",
                "kallsymsReadable",
                "nonZeroAddresses",
                "totalLinesScanned",
                "kptrExposed",
                "kptrRestrictDisabled",
                "nonZeroPointerRatio",
                "modulesReadable",
                "kernelSymbolMatches",
                "hasCjk",
                "hasEmoji",
                "hasTelegram",
                "hasAtMention",
                "customKeywords",
                "bannerSources",
                "bannerConcealableNegatives",
                "hitCount",
                "findings",
            ),
            signalMatcher = {
                it.hasArrayObjectValueOutside("findings", "check", setOf(IDENTITY_MISMATCH_CHECK))
            },
            issueRoutes = listOf(IssueRoute("source", setOf("kallsyms", "modules", "cmdline"))),
            concealableNegativeKey = "bannerConcealableNegatives",
        ),
        UnitPlan(
            "kernel-check.identity-coherence",
            setOf("identityCoherence"),
            signalMatcher = { it.hasArrayObjectValue("findings", "check", setOf(IDENTITY_MISMATCH_CHECK)) },
            issueRoutes = listOf(
                IssueRoute(
                    "source",
                    setOf("zygote_os_version", "proc_sys_kernel_osrelease", "kernel_identity"),
                ),
            ),
            concealableNegativeKey = "identityConcealableNegatives",
            unavailableMatcher = { identityCoherenceState(it) !in setOf("agree", "disagree") },
        ),
    ),
)

private fun identityCoherenceState(payload: JsonObject): String? =
    ((payload["identityCoherence"] as? JsonObject)?.get("state") as? JsonPrimitive)?.content
