package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.IssueRoute
import io.leemikepop.tamperprobe.lab.internal.UnitPlan
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValue
import io.leemikepop.tamperprobe.lab.internal.hasArrayObjectValueOutside

private val ADB_SETTING_FINDING_IDS = setOf("adb_enabled_nonstandard")

internal object DangerousPropsEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter(
    signalUnitId = "dangerous-props.security-posture",
    plans = listOf(
        // The native payload emits overview, observations, findings, telemetry and
        // collectionErrors. "rules" and "properties" were declared here but are never emitted,
        // and "observations" -- the per-property read state that shows which sources answered
        // -- was emitted but declared nowhere, so it was filtered out of both unit reports.
        // collectionErrors is deliberately absent: it is an ISSUE_KEY and is intercepted into
        // the unit's issues rather than published as an attribute.
        //
        // Every property collection error comes from the same bionic source, so they are routed
        // by property: securityPropertyKeys() feed the assessment, posturePropertyKeys() feed the
        // telemetry. ro.debuggable and service.adb.root are read by both (the adb_root_requested
        // telemetry checks them), so they are left unrouted and stay shared.
        //
        // Both units share the findings array and are told apart by finding id, the same way
        // SYSTEM_PROPERTIES_TAMPER splits its two units: adb_enabled_nonstandard is the one rule
        // the environment-posture unit grades, every other finding is a security-posture rule.
        UnitPlan(
            "dangerous-props.security-posture",
            setOf("overview", "observations", "findings"),
            signalMatcher = { payload ->
                payload.hasArrayObjectValueOutside("findings", "id", ADB_SETTING_FINDING_IDS)
            },
            issueRoutes = listOf(
                IssueRoute(
                    "property",
                    setOf(
                        "ro.secure",
                        "ro.build.type",
                        "ro.build.tags",
                        "ro.boot.verifiedbootstate",
                        "ro.boot.flash.locked",
                        "ro.boot.vbmeta.device_state",
                    ),
                ),
            ),
        ),
        // Emulator and ADB-on posture stay research-only telemetry (researchKeys); only the
        // Settings.Global adb_enabled value outside {0, 1} can make this unit a SIGNAL. Its
        // read carries property=adb_enabled, so a failed Settings read marks this unit only.
        //
        // On API 37+ a 0 from that read is not an answer: Android 17 QPR1 returns 0 for
        // adb_enabled to every third-party app. Native publishes it as observation state
        // redacted_by_platform (no value) plus a collectionWarnings entry -- not collectionErrors,
        // because the read itself worked. The same property route claims it, so this unit is
        // PARTIAL with DANGEROUS_PROPS.environment-posture.collectionWarnings while
        // security-posture stays COMPLETE. The rule does not count as answered, so the detector
        // is NOT_OBSERVED when a property rule answered and INCONCLUSIVE only when none did.
        UnitPlan(
            "dangerous-props.environment-posture",
            payloadKeys = setOf("observations", "findings"),
            researchKeys = setOf("telemetry"),
            signalMatcher = { payload ->
                payload.hasArrayObjectValue("findings", "id", ADB_SETTING_FINDING_IDS)
            },
            issueRoutes = listOf(
                IssueRoute(
                    "property",
                    setOf(
                        "ro.boot.qemu",
                        "ro.kernel.qemu",
                        "sys.usb.config",
                        "persist.sys.usb.config",
                        "adb_enabled",
                    ),
                ),
            ),
        ),
    ),
)
