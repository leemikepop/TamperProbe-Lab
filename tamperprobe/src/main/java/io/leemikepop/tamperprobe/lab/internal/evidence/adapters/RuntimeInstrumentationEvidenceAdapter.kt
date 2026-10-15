package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.IssueRoute
import io.leemikepop.tamperprobe.lab.internal.UnitPlan

internal object RuntimeInstrumentationEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "runtime-instrumentation.direct-marker",
    plans = listOf(
        // Descriptor links and the linker list are searched for direct markers only. The maps
        // and thread channels feed both units, so their issues stay unrouted and shared.
        UnitPlan(
            "runtime-instrumentation.direct-marker",
            setOf("directMarkers", "directMarkerCount"),
            issueRoutes = listOf(IssueRoute("source", setOf("/proc/self/fd", "dl_iterate_phdr"))),
        ),
        UnitPlan(
            "runtime-instrumentation.generic-anomaly",
            setOf("genericAnomalies", "genericAnomalyCount", "scannedMappings", "scannedFds", "scannedThreads"),
            researchOnly = true,
        ),
    ),
)
