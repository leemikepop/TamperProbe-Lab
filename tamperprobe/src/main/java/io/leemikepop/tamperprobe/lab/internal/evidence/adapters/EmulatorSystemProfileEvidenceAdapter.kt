package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.UnitPlan
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValue

internal object EmulatorSystemProfileEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "emulator-profile.qemu-properties",
    plans = listOf(
        UnitPlan(
            "emulator-profile.qemu-properties",
            setOf("overview", "properties", "findings"),
            signalMatcher = {
                it.hasArrayObjectValue(
                    "findings",
                    "id",
                    setOf("qemu_system_property", "emulator_boot_property", "virtual_hardware_property"),
                ) || it.hasArrayObjectValue(
                    "findings",
                    "unitId",
                    setOf("emulator-profile.qemu-properties"),
                )
            },
        ),
        UnitPlan(
            "emulator-profile.build-fingerprint",
            setOf("overview", "buildFingerprint", "fingerprintMatched", "findings"),
            signalMatcher = {
                it.hasArrayObjectValue(
                    "findings",
                    "id",
                    setOf("emulator_build_fingerprint", "emulator_product_model"),
                ) || it.hasArrayObjectValue(
                    "findings",
                    "unitId",
                    setOf("emulator-profile.build-fingerprint"),
                )
            },
        ),
    ),
)
