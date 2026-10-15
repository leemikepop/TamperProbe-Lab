package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.IssueRoute
import io.leemikepop.tamperprobe.lab.internal.UnitPlan
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValue

internal object EmulatorHardwareIndicatorsEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "emulator-hardware.egl-renderer",
    plans = listOf(
        UnitPlan(
            "emulator-hardware.egl-renderer",
            setOf("overview", "egl", "findings"),
            signalMatcher = {
                it.hasArrayObjectValue(
                    "findings",
                    "id",
                    setOf("egl_renderer_indicator", "egl_renderer_match"),
                ) || it.hasArrayObjectValue(
                    "findings",
                    "unitId",
                    setOf("emulator-hardware.egl-renderer"),
                )
            },
            issueRoutes = listOf(IssueRoute("source", setOf("egl"))),
        ),
        UnitPlan(
            "emulator-hardware.timer-register-deviation",
            setOf("overview", "timer", "findings"),
            signalMatcher = {
                it.hasArrayObjectValue(
                    "findings",
                    "id",
                    setOf("timer_register_deviation", "arm_timer_deviation"),
                ) || it.hasArrayObjectValue(
                    "findings",
                    "unitId",
                    setOf("emulator-hardware.timer-register-deviation"),
                )
            },
            issueRoutes = listOf(IssueRoute("source", setOf("timer"))),
        ),
        UnitPlan(
            "emulator-hardware.sched-jitter",
            setOf("overview", "schedJitter", "findings"),
            signalMatcher = {
                it.hasArrayObjectValue(
                    "findings",
                    "id",
                    setOf("sched_jitter_anomaly", "sched_yield_jitter_anomaly"),
                ) || it.hasArrayObjectValue(
                    "findings",
                    "unitId",
                    setOf("emulator-hardware.sched-jitter"),
                )
            },
            issueRoutes = listOf(IssueRoute("source", setOf("sched"))),
        ),
    ),
)
