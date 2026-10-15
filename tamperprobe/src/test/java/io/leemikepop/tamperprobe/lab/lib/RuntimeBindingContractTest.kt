package io.leemikepop.tamperprobe.lab.lib

import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.DetectorResult
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitResult
import io.leemikepop.tamperprobe.lab.internal.CatalogParser
import io.leemikepop.tamperprobe.lab.internal.EvidenceAdapterInput
import io.leemikepop.tamperprobe.lab.internal.EvidenceAdapterRegistry
import io.leemikepop.tamperprobe.lab.internal.EvidenceAdaptationException
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RuntimeBindingContractTest {
    private val catalog by lazy { CatalogParser.parse(catalogText()) }
    private val fixtures by lazy {
        Json.parseToJsonElement(fixtureText()).jsonObject
    }

    @Test
    fun everyCatalogDetectorHasExactlyOneRuntimeAdapter() {
        assertEquals(catalog.descriptors.map { it.id }.toSet(), EvidenceAdapterRegistry.bindingIds)
    }

    @Test
    fun successfulNeutralResultsPublishEveryDeclaredUnit() {
        catalog.descriptors.forEach { descriptor ->
            val results = EvidenceAdapterRegistry.map(
                EvidenceAdapterInput(
                    descriptor,
                    DetectionOutcome.NOT_OBSERVED,
                    EvidenceStrength.NONE,
                    payloadFor(descriptor.id, DetectionOutcome.NOT_OBSERVED),
                ),
            )
            assertEquals(descriptor.evidenceUnits, results.map { it.descriptor })
            assertTrue(results.all { it.records.isNotEmpty() || it.issues.isNotEmpty() })
            assertTrue(results.flatMap { it.records }.none { it.kind == EvidenceRecordKind.SIGNAL })
        }
    }

    @Test
    fun observedResultsPublishExplicitStrengthBearingSignals() {
        catalog.descriptors.forEach { descriptor ->
            val expectedStrength = if (descriptor.id == "DANGEROUS_PACKAGES") {
                EvidenceStrength.WEAK
            } else {
                EvidenceStrength.MODERATE
            }
            val records = EvidenceAdapterRegistry.map(
                EvidenceAdapterInput(
                    descriptor,
                    DetectionOutcome.OBSERVED,
                    expectedStrength,
                    payloadFor(descriptor.id, DetectionOutcome.OBSERVED),
                ),
            ).flatMap { it.records }
            val signals = records.filter { it.kind == EvidenceRecordKind.SIGNAL }

            assertTrue("${descriptor.id} must publish a signal", signals.isNotEmpty())
            assertTrue(signals.all { it.signalStrength == expectedStrength })
            assertTrue(records.filter { it.kind != EvidenceRecordKind.SIGNAL }.all { it.signalStrength == null })
        }
    }

    @Test
    fun inconclusivePayloadPublishesIssuesWithoutSignals() {
        catalog.descriptors.forEach { descriptor ->
            val results = EvidenceAdapterRegistry.map(
                EvidenceAdapterInput(
                    descriptor,
                    DetectionOutcome.INCONCLUSIVE,
                    EvidenceStrength.NONE,
                    payloadFor(descriptor.id, DetectionOutcome.INCONCLUSIVE),
                ),
            )
            assertTrue(results.all { it.issues.isNotEmpty() })
            assertTrue(results.flatMap { it.records }.none { it.kind == EvidenceRecordKind.SIGNAL })
        }
    }

    @Test
    fun publicRecordCodesDoNotEncodeLegacyRoles() {
        val forbidden = listOf(".finding.", ".diagnostic.", ".telemetry.", ".collection_warning.")
        catalog.descriptors.forEach { descriptor ->
            val records = EvidenceAdapterRegistry.map(
                EvidenceAdapterInput(
                    descriptor,
                    DetectionOutcome.OBSERVED,
                    EvidenceStrength.WEAK,
                    payloadFor(descriptor.id, DetectionOutcome.OBSERVED),
                ),
            ).flatMap { it.records }
            assertFalse(records.any { record -> forbidden.any { it in record.code } })
            assertTrue(records.all { it.code.matches(Regex("^[A-Z0-9_]+\\.[a-z0-9-]+\\.[a-z0-9-]+$")) })
        }
    }

    @Test
    fun dangerousPackageSignalsAreBoundToTheUnitThatObservedTheObject() {
        val descriptor = catalog.descriptors.single { it.id == "DANGEROUS_PACKAGES" }
        val payload = buildJsonObject {
            put("packageIdentity", buildJsonObject {
                put("targetCount", 1)
                put("completedQueryCount", 1)
                put("visiblePackageCount", 361)
                put("detectedPackages", buildJsonArray { add(JsonPrimitive("com.example.root")) })
                put("issues", buildJsonArray {})
            })
            put("appDataPath", buildJsonObject {
                put("attemptedPathCount", 2)
                put("completedPathCount", 2)
                put("notFoundPathCount", 1)
                put("foundPaths", buildJsonArray { add(JsonPrimitive("/data/user/0/com.example.root")) })
                put("inaccessiblePaths", buildJsonArray {})
                put("issues", buildJsonArray {})
            })
        }

        val results = EvidenceAdapterRegistry.map(
            EvidenceAdapterInput(descriptor, DetectionOutcome.OBSERVED, EvidenceStrength.WEAK, payload),
        )

        assertEquals(
            setOf(
                "dangerous-packages.package-identity-visibility",
                "dangerous-packages.app-data-path-visibility",
            ),
            results.filter { result -> result.records.any { it.kind == EvidenceRecordKind.SIGNAL } }
                .map { it.descriptor.id }
                .toSet(),
        )
        val packageUnit = results.single { it.descriptor.id == "dangerous-packages.package-identity-visibility" }
        assertEquals("361", packageUnit.records.single().attributes["visiblePackageCount"])
    }

    @Test
    fun appDataIsolationLeavesThePathUnitUnavailableWithoutBlockingTheVerdict() {
        val descriptor = catalog.descriptors.single { it.id == "DANGEROUS_PACKAGES" }
        val payload = buildJsonObject {
            put("packageIdentity", buildJsonObject {
                put("targetCount", 78)
                put("completedQueryCount", 78)
                put("visiblePackageCount", 288)
                put("detectedPackages", buildJsonArray {})
                put("issues", buildJsonArray {})
            })
            put("appDataPath", buildJsonObject {
                put("attemptedPathCount", 156)
                put("completedPathCount", 0)
                put("notFoundPathCount", 0)
                put("foundPaths", buildJsonArray {})
                put("inaccessiblePaths", buildJsonArray {})
                put("unconfirmedNotFoundCount", 156)
                put("selfControl", "exists")
                put("crossPackageControl", "not_found")
                put("isolationDetected", true)
                put("issues", buildJsonArray {
                    add(buildJsonObject {
                        put("code", "app-data-isolated")
                        put("message", "Other applications' data directories are not visible")
                        put("attributes", buildJsonObject {
                            put("selfControl", "exists")
                            put("crossPackageControl", "not_found")
                        })
                    })
                })
            })
        }

        // NOT_OBSERVED must be accepted: the package unit answered, and isolation is
        // structural. Before this change the adapter expected INCONCLUSIVE here.
        val results = EvidenceAdapterRegistry.map(
            EvidenceAdapterInput(descriptor, DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE, payload),
        )

        val packageUnit = results.single { it.descriptor.id == "dangerous-packages.package-identity-visibility" }
        val pathUnit = results.single { it.descriptor.id == "dangerous-packages.app-data-path-visibility" }
        assertEquals(EvidenceUnitCollectionStatus.COMPLETE, packageUnit.collectionStatus)
        assertEquals(EvidenceUnitCollectionStatus.UNAVAILABLE, pathUnit.collectionStatus)
        assertTrue(pathUnit.issues.any { it.code.endsWith(".app-data-isolated") })
        assertTrue(pathUnit.records.none { it.kind == EvidenceRecordKind.SIGNAL })
    }

    @Test
    fun anUnavailableTargetListDecodesAsInconclusiveInsteadOfFailingTheDetector() {
        val descriptor = catalog.descriptors.single { it.id == "DANGEROUS_PACKAGES" }
        fun unavailable() = buildJsonArray {
            add(buildJsonObject {
                put("code", "target-list-unavailable")
                put("message", "Unable to collect target package names")
                put("attributes", buildJsonObject {})
            })
        }
        // The shape dangerous_packages.cpp now returns when the target list cannot be read.
        val payload = buildJsonObject {
            put("packageIdentity", buildJsonObject {
                put("targetCount", 0)
                put("completedQueryCount", 0)
                put("visiblePackageCount", -1)
                put("detectedPackages", buildJsonArray {})
                put("issues", unavailable())
            })
            put("appDataPath", buildJsonObject {
                put("attemptedPathCount", 0)
                put("completedPathCount", 0)
                put("notFoundPathCount", 0)
                put("foundPaths", buildJsonArray {})
                put("inaccessiblePaths", buildJsonArray {})
                put("unconfirmedNotFoundCount", 0)
                put("selfControl", "not_attempted")
                put("crossPackageControl", "not_attempted")
                put("isolationDetected", false)
                put("issues", unavailable())
            })
        }

        val results = EvidenceAdapterRegistry.map(
            EvidenceAdapterInput(descriptor, DetectionOutcome.INCONCLUSIVE, EvidenceStrength.NONE, payload),
        )

        assertEquals(2, results.size)
        assertTrue(results.all { it.collectionStatus == EvidenceUnitCollectionStatus.UNAVAILABLE })
        assertTrue(results.all { result -> result.issues.any { it.code.endsWith(".target-list-unavailable") } })
    }

    @Test
    fun dangerousPackageAssessmentCannotClaimSignalWithoutObservedObject() {
        val descriptor = catalog.descriptors.single { it.id == "DANGEROUS_PACKAGES" }
        val error = assertThrows(EvidenceAdaptationException::class.java) {
            EvidenceAdapterRegistry.map(
                EvidenceAdapterInput(
                    descriptor,
                    DetectionOutcome.OBSERVED,
                    EvidenceStrength.WEAK,
                    payloadFor(descriptor.id, DetectionOutcome.NOT_OBSERVED),
                ),
            )
        }

        assertEquals("PAYLOAD_ASSESSMENT_MISMATCH", error.code)
    }

    @Test
    fun dangerousPackageUnitsExposeIndependentCollectionStatus() {
        val descriptor = catalog.descriptors.single { it.id == "DANGEROUS_PACKAGES" }
        val payload = buildJsonObject {
            put("packageIdentity", buildJsonObject {
                put("targetCount", 1)
                put("completedQueryCount", 0)
                put("detectedPackages", buildJsonArray {})
                put("issues", buildJsonArray { add(issue("package-manager-unavailable")) })
            })
            put("appDataPath", buildJsonObject {
                put("attemptedPathCount", 2)
                put("completedPathCount", 2)
                put("notFoundPathCount", 2)
                put("foundPaths", buildJsonArray {})
                put("inaccessiblePaths", buildJsonArray {})
                put("issues", buildJsonArray {})
            })
        }

        val results = EvidenceAdapterRegistry.map(
            EvidenceAdapterInput(descriptor, DetectionOutcome.INCONCLUSIVE, EvidenceStrength.NONE, payload),
        )

        assertEquals(
            EvidenceUnitCollectionStatus.UNAVAILABLE,
            results.single { it.descriptor.id.endsWith("package-identity-visibility") }.collectionStatus,
        )
        assertEquals(
            EvidenceUnitCollectionStatus.COMPLETE,
            results.single { it.descriptor.id.endsWith("app-data-path-visibility") }.collectionStatus,
        )
    }

    @Test
    fun dangerousPackageBindingRejectsMissingDeclaredUnitPayload() {
        val descriptor = catalog.descriptors.single { it.id == "DANGEROUS_PACKAGES" }
        val error = assertThrows(EvidenceAdaptationException::class.java) {
            EvidenceAdapterRegistry.map(
                EvidenceAdapterInput(
                    descriptor,
                    DetectionOutcome.NOT_OBSERVED,
                    EvidenceStrength.NONE,
                    buildJsonObject {
                        put("packageIdentity", buildJsonObject {
                            put("targetCount", 1)
                            put("completedQueryCount", 1)
                            put("detectedPackages", buildJsonArray {})
                            put("issues", buildJsonArray {})
                        })
                    },
                ),
            )
        }

        assertEquals("PAYLOAD_DECODE_FAILED", error.code)
    }

    @Test
    fun packageStorageVisibilityUnicodeAliasBindsToPathVisibilityAsSignalAndDifferentialIsResearchOnly() {
        val descriptor = catalog.descriptors.single { it.id == "PACKAGE_STORAGE_VISIBILITY" }
        val payload = buildJsonObject {
            put("storageContext", buildJsonObject {
                put("userId", 0)
                put("storageRoot", "/storage/emulated/0")
                put("statfsAvailable", true)
                put("fuseBpfState", "unavailable")
                put("appDataIsolationState", "unavailable")
                put("rootProbe", buildJsonObject {
                    put("state", "present")
                    put("errno", 0)
                })
            })
            put("overview", buildJsonObject {
                put("targetCount", 1)
                put("completedBaselineCount", 2)
                put("transformedProbeCount", 138)
                put("candidateCount", 1)
                put("findingCount", 1)
                put("telemetryCount", 1)
                put("droppedObservationCount", 0)
                put("droppedCollectionErrorCount", 0)
            })
            put("packageObservations", buildJsonArray {})
            put("findings", buildJsonArray {
                add(buildJsonObject {
                    put("id", "unicode_alias")
                    put("package", "com.topjohnwu.magisk")
                    put("protectedRoot", "data")
                    put("variantId", "zero_width_space_android_inside")
                    put("codePoint", "U+200B")
                    put("placement", "android_inside")
                    put("strength", "weak")
                    put("classification", "package_data_artifact")
                    put("summary", "Unicode storage alias reveals a dangerous-package artifact")
                })
            })
            put("telemetry", buildJsonArray {
                add(buildJsonObject {
                    put("id", "platform_oracle")
                    put("classification", "storage_isolation_behavior")
                    put("assessmentImpact", "telemetry_only")
                    put("summary", "Storage path aliases produced a platform-level behavioral differential")
                    put("differentialCount", 1)
                })
            })
            put("collectionErrors", buildJsonArray {})
        }

        val results = EvidenceAdapterRegistry.map(
            EvidenceAdapterInput(descriptor, DetectionOutcome.OBSERVED, EvidenceStrength.WEAK, payload),
        )

        val pathVisibility = results.single { it.descriptor.id == "package-storage.path-visibility" }
        val differential = results.single { it.descriptor.id == "package-storage.path-representation-differential" }

        assertTrue(pathVisibility.records.any { it.kind == EvidenceRecordKind.SIGNAL })
        assertTrue(differential.records.none { it.kind == EvidenceRecordKind.SIGNAL })
        assertTrue(differential.records.any { it.kind == EvidenceRecordKind.RESEARCH })
    }

    @Test
    fun researchOnlyRuntimeAnomalyNeverBecomesASignal() {
        val descriptor = catalog.descriptors.single { it.id == "RUNTIME_INSTRUMENTATION" }
        val payload = buildJsonObject {
            put("genericAnomalies", buildJsonArray { add(buildJsonObject { put("value", "memfd") }) })
        }

        val results = EvidenceAdapterRegistry.map(
            EvidenceAdapterInput(descriptor, DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE, payload),
        )
        val generic = results.single { it.descriptor.id == "runtime-instrumentation.generic-anomaly" }

        assertTrue(generic.records.any { it.kind == EvidenceRecordKind.RESEARCH })
        assertTrue(generic.records.none { it.kind == EvidenceRecordKind.SIGNAL })
    }

    @Test
    fun issueOnlyPayloadIsUnavailableRatherThanPartial() {
        val descriptor = catalog.descriptors.single { it.id == "MEMORY_FD_ANOMALY" }
        val payload = buildJsonObject {
            put(
                "collectionErrors",
                buildJsonArray { add(buildJsonObject { put("message", "maps unavailable") }) },
            )
        }

        val result = EvidenceAdapterRegistry.map(
            EvidenceAdapterInput(descriptor, DetectionOutcome.INCONCLUSIVE, EvidenceStrength.NONE, payload),
        ).single()

        assertEquals(EvidenceUnitCollectionStatus.UNAVAILABLE, result.collectionStatus)
        assertTrue(result.records.isEmpty())
        assertTrue(result.issues.isNotEmpty())
    }

    @Test
    fun descriptorForensicsTrapChannelNeverPublishesASignal() {
        val descriptor = catalog.descriptors.single { it.id == "ZYGISK_FD_FORENSICS" }
        val results = EvidenceAdapterRegistry.map(
            EvidenceAdapterInput(
                descriptor,
                DetectionOutcome.OBSERVED,
                EvidenceStrength.MODERATE,
                payloadFor(descriptor.id, DetectionOutcome.OBSERVED),
            ),
        )

        val trapUnit = results.single { it.descriptor.id == "zygisk-fd-forensics.cross-process-trap" }
        assertTrue(
            "The trap channel is telemetry only and must never carry a signal",
            trapUnit.records.none { it.kind == EvidenceRecordKind.SIGNAL },
        )
        assertEquals(
            setOf("zygisk-fd-forensics.descriptor-view-differential"),
            results.filter { result -> result.records.any { it.kind == EvidenceRecordKind.SIGNAL } }
                .map { it.descriptor.id }
                .toSet(),
        )
    }

    @Test
    fun descriptorForensicsSignalRequiresAViewContradictionFinding() {
        val descriptor = catalog.descriptors.single { it.id == "ZYGISK_FD_FORENSICS" }
        val payload = buildJsonObject {
            put("overview", buildJsonObject {
                put("hostConfirmedCount", 0)
                put("carrierConfirmedCount", 0)
                put("findingCount", 0)
            })
            put("hostProcess", buildJsonObject { put("confirmedCount", 0) })
            put("carrierProcess", buildJsonObject { put("available", true) })
            // A trap descriptor that failed every Duck-Detector check must still not
            // produce a signal, because that channel cannot observe specialization.
            put("trapChannel", buildJsonObject {
                put("carrierStatus", "closed_ebadf")
                put("assessmentImpact", "telemetry_only")
            })
            put("findings", buildJsonArray {})
        }

        val results = EvidenceAdapterRegistry.map(
            EvidenceAdapterInput(descriptor, DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE, payload),
        )

        assertTrue(results.flatMap { it.records }.none { it.kind == EvidenceRecordKind.SIGNAL })
    }

    @Test
    fun propertySourceGradingIdsAllBindToTheSourceConsistencyUnit() {
        val descriptor = catalog.descriptors.single { it.id == "SYSTEM_PROPERTIES_TAMPER" }
        val gradedIds = listOf(
            "property_source_mismatch",
            "property_accessor_contradiction",
            "property_snapshot_drift",
            "boot_property_inconsistency",
        )

        gradedIds.forEach { findingId ->
            val payload = buildJsonObject {
                put("findings", buildJsonArray {
                    add(
                        buildJsonObject {
                            put("id", findingId)
                            put("property", "ro.boot.verifiedbootstate")
                            put("outlierSources", buildJsonArray { add(JsonPrimitive("bionic_legacy")) })
                        },
                    )
                })
                put("comparisons", buildJsonArray {})
                put("sources", buildJsonArray {})
                put("propertyAreas", buildJsonArray {})
            }

            val signalUnits = EvidenceAdapterRegistry.map(
                EvidenceAdapterInput(
                    descriptor,
                    DetectionOutcome.OBSERVED,
                    EvidenceStrength.MODERATE,
                    payload,
                ),
            ).filter { result -> result.records.any { it.kind == EvidenceRecordKind.SIGNAL } }
                .map { it.descriptor.id }

            assertEquals(
                "$findingId must bind to the source-consistency unit",
                listOf("system-properties.source-consistency"),
                signalUnits,
            )
        }
    }

    @Test
    fun propertyAreaHoleDoesNotSignalTheSourceConsistencyUnit() {
        val descriptor = catalog.descriptors.single { it.id == "SYSTEM_PROPERTIES_TAMPER" }
        val payload = buildJsonObject {
            put("findings", buildJsonArray {
                add(
                    buildJsonObject {
                        put("id", "prop_area_unreferenced_hole")
                        put("property", "/dev/__properties__/u:object_r:default_prop:s0")
                    },
                )
            })
            put("comparisons", buildJsonArray {})
            put("sources", buildJsonArray {})
            put("propertyAreas", buildJsonArray {})
        }

        val signalUnits = EvidenceAdapterRegistry.map(
            EvidenceAdapterInput(descriptor, DetectionOutcome.OBSERVED, EvidenceStrength.STRONG, payload),
        ).filter { result -> result.records.any { it.kind == EvidenceRecordKind.SIGNAL } }
            .map { it.descriptor.id }

        assertEquals(listOf("system-properties.area-layout"), signalUnits)
    }

    @Test
    fun dangerousPropsFindingsBindToTheUnitWhoseRuleProducedThem() {
        // adb_enabled_nonstandard is the one rule the environment-posture unit grades; every
        // other finding belongs to security-posture. Emulator and ADB-on telemetry stays RESEARCH.
        val cases = listOf(
            listOf("adb_enabled_nonstandard") to listOf("dangerous-props.environment-posture"),
            listOf("debuggable_build") to listOf("dangerous-props.security-posture"),
            listOf("debuggable_build", "adb_enabled_nonstandard") to listOf(
                "dangerous-props.security-posture",
                "dangerous-props.environment-posture",
            ),
        )
        cases.forEach { (findingIds, expectedSignalUnits) ->
            val units = mapDangerousProps(DetectionOutcome.OBSERVED, EvidenceStrength.WEAK, findingIds)
            val signalUnits = units
                .filter { unit -> unit.records.any { it.kind == EvidenceRecordKind.SIGNAL } }
                .map { it.descriptor.id }

            assertEquals(findingIds.toString(), expectedSignalUnits, signalUnits)
            val environment = units.single { it.descriptor.id == "dangerous-props.environment-posture" }
            val research = environment.records.single { it.kind == EvidenceRecordKind.RESEARCH }
            assertTrue(findingIds.toString(), research.attributes.keys.any { it.startsWith("telemetry.") })
            assertTrue(findingIds.toString(), research.attributes.keys.none { it.startsWith("findings.") })
        }
    }

    @Test
    fun aStandardAdbEnabledValueLeavesEnvironmentPostureWithoutASignal() {
        // adb_enabled=1 is ordinary developer posture: NOT_OBSERVED, the raw value published as
        // an OBSERVATION, the ADB transport telemetry still RESEARCH.
        val units = mapDangerousProps(DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE, emptyList())
        val environment = units.single { it.descriptor.id == "dangerous-props.environment-posture" }

        assertEquals(EvidenceUnitCollectionStatus.COMPLETE, environment.collectionStatus)
        assertTrue(environment.records.none { it.kind == EvidenceRecordKind.SIGNAL })
        val observation = environment.records.single { it.kind == EvidenceRecordKind.OBSERVATION }
        val settingIndex = observation.attributes.entries
            .single { it.key.endsWith(".source") && it.value == "settings_global" }
            .key.removeSuffix(".source")
        assertEquals("adb_enabled", observation.attributes["$settingIndex.property"])
        assertEquals("1", observation.attributes["$settingIndex.value"])
        assertTrue(environment.records.any { it.kind == EvidenceRecordKind.RESEARCH })
    }

    @Test
    fun anUnreadableAdbEnabledSettingIsAnIssueNeverAClean() {
        val results = mapWithErrors(
            "DANGEROUS_PROPS",
            DetectionOutcome.NOT_OBSERVED,
            collectionError("source" to "settings_global", "property" to "adb_enabled"),
        ).associateBy { it.descriptor.id }

        val environment = results.getValue("dangerous-props.environment-posture")
        assertEquals(EvidenceUnitCollectionStatus.PARTIAL, environment.collectionStatus)
        assertEquals(
            listOf("DANGEROUS_PROPS.environment-posture.collectionErrors"),
            environment.issues.map { it.code },
        )
        assertEquals("settings_global", environment.issues.single().attributes["0.source"])
        assertEquals(
            EvidenceUnitCollectionStatus.COMPLETE,
            results.getValue("dangerous-props.security-posture").collectionStatus,
        )
    }

    @Test
    fun aPlatformRedactedAdbEnabledIsAWarningOnEnvironmentPostureNeverAClean() {
        // Android 17 QPR1 (API 37) returns adb_enabled = 0 to every third-party app. Native
        // publishes that read as redacted_by_platform, without a value, plus a collectionWarnings
        // entry; the property rules still answered, so the detector is NOT_OBSERVED.
        val descriptor = catalog.descriptors.single { it.id == "DANGEROUS_PROPS" }
        val replaced = setOf("observations", "findings", "collectionErrors", "collectionWarnings")
        val payload = buildJsonObject {
            fixtures.getValue("DANGEROUS_PROPS").jsonObject.forEach { (key, value) ->
                if (key !in replaced) put(key, value)
            }
            put("observations", buildJsonArray {
                add(buildJsonObject {
                    put("property", "ro.secure")
                    put("source", "bionic")
                    put("state", "present")
                    put("value", "1")
                })
                add(buildJsonObject {
                    put("property", "sys.usb.config")
                    put("source", "bionic")
                    put("state", "present")
                    put("value", "adb")
                })
                add(buildJsonObject {
                    put("property", "adb_enabled")
                    put("source", "settings_global")
                    put("state", "redacted_by_platform")
                    put("apiLevel", 37)
                })
            })
            put("findings", buildJsonArray {})
            put("collectionErrors", buildJsonArray {})
            put("collectionWarnings", buildJsonArray {
                add(buildJsonObject {
                    put("source", "settings_global")
                    put("property", "adb_enabled")
                    put("state", "redacted_by_platform")
                    put("apiLevel", 37)
                    put("detail", "fixture platform redaction")
                })
            })
        }

        val units = EvidenceAdapterRegistry.map(
            EvidenceAdapterInput(descriptor, DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE, payload),
        ).associateBy { it.descriptor.id }

        val environment = units.getValue("dangerous-props.environment-posture")
        assertEquals(EvidenceUnitCollectionStatus.PARTIAL, environment.collectionStatus)
        assertEquals(
            listOf("DANGEROUS_PROPS.environment-posture.collectionWarnings"),
            environment.issues.map { it.code },
        )
        val warning = environment.issues.single().attributes
        assertEquals("adb_enabled", warning["0.property"])
        assertEquals("redacted_by_platform", warning["0.state"])
        assertEquals("37", warning["0.apiLevel"])
        assertTrue(environment.records.none { it.kind == EvidenceRecordKind.SIGNAL })
        val observation = environment.records.single { it.kind == EvidenceRecordKind.OBSERVATION }
        val settingIndex = observation.attributes.entries
            .single { it.key.endsWith(".source") && it.value == "settings_global" }
            .key.removeSuffix(".source")
        assertEquals("redacted_by_platform", observation.attributes["$settingIndex.state"])
        assertFalse(observation.attributes.containsKey("$settingIndex.value"))

        val security = units.getValue("dangerous-props.security-posture")
        assertEquals(EvidenceUnitCollectionStatus.COMPLETE, security.collectionStatus)
        assertTrue(security.issues.isEmpty())
    }

    @Test
    fun aChannelOwnedByOneUnitLeavesItsSiblingUnitsComplete() {
        val results = mapWithErrors(
            "EMULATOR_HARDWARE_INDICATORS",
            DetectionOutcome.NOT_OBSERVED,
            collectionError("source" to "egl"),
        ).associateBy { it.descriptor.id }

        val egl = results.getValue("emulator-hardware.egl-renderer")
        assertEquals(EvidenceUnitCollectionStatus.PARTIAL, egl.collectionStatus)
        assertEquals(
            listOf("EMULATOR_HARDWARE_INDICATORS.egl-renderer.collectionErrors"),
            egl.issues.map { it.code },
        )
        assertEquals("egl", egl.issues.single().attributes["0.source"])
        listOf("emulator-hardware.timer-register-deviation", "emulator-hardware.sched-jitter").forEach { id ->
            val sibling = results.getValue(id)
            assertEquals(id, EvidenceUnitCollectionStatus.COMPLETE, sibling.collectionStatus)
            assertTrue(id, sibling.issues.isEmpty())
        }
    }

    @Test
    fun selinuxReadDenialInferenceCompletesEnforcementStateOnTheFleetShape() {
        // The fleet's measured shape: libselinux is outside the app's linker namespace and the
        // enforce node read is EACCES. With the read-denial inference that refusal answers
        // ENFORCING, native raises no selinuxfs_enforce issue, and only the libselinux gap
        // remains - which leaves the cross-source unit without a second view.
        val results = mapSelinux(
            DetectionOutcome.NOT_OBSERVED,
            readDenialInferred = true,
            collectionError("source" to "libselinux"),
        ).associateBy { it.descriptor.id }

        listOf("selinux.enforcement-state", "selinux.enforce-node-access").forEach { id ->
            val unit = results.getValue(id)
            assertEquals(id, EvidenceUnitCollectionStatus.COMPLETE, unit.collectionStatus)
            assertTrue(id, unit.issues.isEmpty())
        }
        val enforcement = results.getValue("selinux.enforcement-state")
        val attributes = enforcement.records.single { it.kind == EvidenceRecordKind.OBSERVATION }.attributes
        assertEquals("inferred", attributes["readDenialInference.state"])
        assertEquals("kernel_constant", attributes["readDenialInference.dacBasis"])
        assertEquals("app_domain", attributes["readDenialInference.scope"])
        assertTrue(attributes.entries.any { it.value == "selinuxfs_read_denial" })

        val crossSource = results.getValue("selinux.cross-source-consistency")
        assertEquals(EvidenceUnitCollectionStatus.PARTIAL, crossSource.collectionStatus)
        assertEquals(setOf("libselinux"), issueSources(crossSource))
    }

    @Test
    fun selinuxWithNoAnsweringSourceMarksEnforcementStateThroughItsOwnIssue() {
        // Inference not possible (for example stat() shows no other-read): the read failure,
        // the libselinux failure and the native "no source answered" entry are all reported.
        val results = mapSelinux(
            DetectionOutcome.INCONCLUSIVE,
            readDenialInferred = false,
            collectionError("source" to "selinuxfs_enforce", "errno" to "13"),
            collectionError("source" to "libselinux"),
            collectionError("source" to "enforcement_sources"),
        ).associateBy { it.descriptor.id }

        val enforcement = results.getValue("selinux.enforcement-state")
        assertEquals(EvidenceUnitCollectionStatus.PARTIAL, enforcement.collectionStatus)
        assertEquals(setOf("enforcement_sources"), issueSources(enforcement))
        val crossSource = results.getValue("selinux.cross-source-consistency")
        assertEquals(
            setOf("selinuxfs_enforce", "libselinux", "enforcement_sources"),
            issueSources(crossSource),
        )
        assertTrue(results.values.flatMap { it.records }.none { it.kind == EvidenceRecordKind.SIGNAL })
    }

    @Test
    fun anInferredEnforcementContradictionSignalsTheCrossSourceUnit() {
        val descriptor = catalog.descriptors.single { it.id == "SELINUX_CHECK" }
        val payload = buildJsonObject {
            selinuxPayload(readDenialInferred = true).forEach { (key, value) ->
                if (key != "findings") put(key, value)
            }
            put("findings", buildJsonArray {
                listOf("inferred_enforcement_contradiction", "selinux_permissive").forEach { id ->
                    add(buildJsonObject {
                        put("id", id)
                        put("strength", "moderate")
                        put("summary", id)
                        put("detail", id)
                    })
                }
            })
        }
        val results = EvidenceAdapterRegistry.map(
            EvidenceAdapterInput(descriptor, DetectionOutcome.OBSERVED, EvidenceStrength.MODERATE, payload),
        ).associateBy { it.descriptor.id }

        listOf("selinux.enforcement-state", "selinux.cross-source-consistency").forEach { id ->
            val signal = results.getValue(id).records.single { it.kind == EvidenceRecordKind.SIGNAL }
            assertEquals(id, EvidenceStrength.MODERATE, signal.signalStrength)
        }
        assertTrue(
            results.getValue("selinux.enforce-node-access").records.none { it.kind == EvidenceRecordKind.SIGNAL },
        )
    }

    private fun issueSources(unit: EvidenceUnitResult): Set<String> =
        unit.issues.flatMap { it.attributes.filterKeys { key -> key.endsWith(".source") }.values }.toSet()

    private fun selinuxPayload(readDenialInferred: Boolean): JsonObject = buildJsonObject {
        fixtures.getValue("SELINUX_CHECK").jsonObject.forEach { (key, value) ->
            if (key !in setOf("enforcementSources", "readDenialInference", "collectionErrors")) put(key, value)
        }
        put("enforcementSources", buildJsonArray {
            add(buildJsonObject {
                put("source", "selinuxfs_enforce")
                put("state", "unavailable")
                put("mode", "unknown")
                put("error", "Permission denied")
                put("errno", 13)
            })
            add(buildJsonObject {
                put("source", "selinuxfs_read_denial")
                put("state", if (readDenialInferred) "present" else "unavailable")
                put("mode", if (readDenialInferred) "enforcing" else "unknown")
                if (!readDenialInferred) put("error", "dac_denies_read")
            })
            add(buildJsonObject {
                put("source", "libselinux")
                put("state", "unavailable")
                put("mode", "unknown")
                put("error", "library not found")
            })
        })
        put("readDenialInference", buildJsonObject {
            put("readErrno", 13)
            put("readStep", "open")
            put("state", if (readDenialInferred) "inferred" else "not_inferred")
            if (readDenialInferred) {
                put("stat", buildJsonObject {
                    put("state", "unavailable")
                    put("errno", 13)
                    put("error", "Permission denied")
                })
                put("reason", "eacces_on_dac_readable_node")
                put("dacBasis", "kernel_constant")
                put("dacPermitsRead", true)
                put("kernelMode", "0644")
                put("scope", "app_domain")
            } else {
                put("stat", buildJsonObject {
                    put("state", "present")
                    put("mode", "0640")
                    put("fileType", "regular")
                    put("uid", 0)
                    put("gid", 0)
                })
                put("reason", "dac_denies_read")
                put("dacBasis", "measured_mode")
                put("dacPermitsRead", false)
                put("anomaly", "enforce_node_dac_not_kernel_default")
            }
        })
    }

    private fun mapSelinux(
        outcome: DetectionOutcome,
        readDenialInferred: Boolean,
        vararg errors: JsonObject,
    ): List<EvidenceUnitResult> {
        val descriptor = catalog.descriptors.single { it.id == "SELINUX_CHECK" }
        val payload = buildJsonObject {
            selinuxPayload(readDenialInferred).forEach { (key, value) -> put(key, value) }
            put("collectionErrors", buildJsonArray { errors.forEach { add(it) } })
        }
        return EvidenceAdapterRegistry.map(EvidenceAdapterInput(descriptor, outcome, EvidenceStrength.NONE, payload))
    }

    @Test
    fun unitAttributionCoversEveryChannelThatFeedsOnlyPartOfADetector() {
        // detector, error source field and value, units that must not be marked by it
        val cases = listOf(
            Triple("MOUNT_INTEGRITY", "source" to "statx", setOf("mount-integrity.kernel-view-consistency")),
            Triple(
                "RUNTIME_INSTRUMENTATION",
                "source" to "/proc/self/fd",
                setOf("runtime-instrumentation.direct-marker"),
            ),
            Triple(
                "RUNTIME_INSTRUMENTATION",
                "source" to "dl_iterate_phdr",
                setOf("runtime-instrumentation.direct-marker"),
            ),
            Triple(
                "ZYGISK_FD_FORENSICS",
                "source" to "host_process",
                setOf("zygisk-fd-forensics.descriptor-view-differential"),
            ),
            Triple("DANGEROUS_PROPS", "property" to "ro.secure", setOf("dangerous-props.security-posture")),
            Triple("DANGEROUS_PROPS", "property" to "sys.usb.config", setOf("dangerous-props.environment-posture")),
            Triple("DANGEROUS_PROPS", "property" to "adb_enabled", setOf("dangerous-props.environment-posture")),
            Triple(
                "SYSTEM_PROPERTIES_TAMPER",
                "property" to "ro.boot.verifiedbootstate",
                setOf("system-properties.source-consistency"),
            ),
            Triple(
                "SELINUX_CHECK",
                "source" to "process_context",
                setOf("selinux.enforcement-state"),
            ),
            Triple(
                "SELINUX_CHECK",
                "source" to "write_probe",
                setOf("selinux.enforce-node-access", "selinux.cross-source-consistency"),
            ),
            Triple("SELINUX_CHECK", "source" to "selinuxfs_enforce", setOf("selinux.cross-source-consistency")),
            Triple("SELINUX_CHECK", "source" to "libselinux", setOf("selinux.cross-source-consistency")),
            Triple(
                "SELINUX_CHECK",
                "source" to "enforcement_sources",
                setOf("selinux.enforcement-state", "selinux.cross-source-consistency"),
            ),
        )

        cases.forEach { (detectorId, field, expectedUnits) ->
            val label = "$detectorId ${field.second}"
            val results = mapWithErrors(detectorId, DetectionOutcome.NOT_OBSERVED, collectionError(field))
            val marked = results.filter { it.issues.isNotEmpty() }.map { it.descriptor.id }.toSet()

            assertEquals(label, expectedUnits, marked)
            assertTrue(label, results.flatMap { it.issues }.none { it.code.endsWith(".shared") })
            results.filter { it.descriptor.id !in expectedUnits }.forEach {
                assertEquals(label, EvidenceUnitCollectionStatus.COMPLETE, it.collectionStatus)
            }
        }
    }

    @Test
    fun aChannelEveryUnitSharesIsPublishedOnEveryUnitAsShared() {
        // mountinfo backs all three viewpoints, so it is deliberately unrouted.
        val results = mapWithErrors(
            "MOUNT_INTEGRITY",
            DetectionOutcome.NOT_OBSERVED,
            collectionError("source" to "/proc/self/mountinfo"),
        )

        assertEquals(3, results.size)
        results.forEach { unit ->
            val localId = unit.descriptor.id.substringAfter('.')
            assertEquals(EvidenceUnitCollectionStatus.PARTIAL, unit.collectionStatus)
            assertEquals(
                listOf("MOUNT_INTEGRITY.$localId.collectionErrors.shared"),
                unit.issues.map { it.code },
            )
        }
    }

    @Test
    fun anUnrecognisedIssueEntryFallsBackToEveryUnitRatherThanDisappearing() {
        // A source native renames or newly introduces, an entry without the routed field, and
        // a scalar issue value can all not be attributed. None of them may be dropped.
        val payload = buildJsonObject {
            fixtures.getValue("EMULATOR_HARDWARE_INDICATORS").jsonObject.forEach { (key, value) -> put(key, value) }
            put("collectionErrors", buildJsonArray {
                add(collectionError("source" to "egl"))
                add(collectionError("source" to "gpu_counter"))
                add(buildJsonObject {})
            })
            put("collectionError", "native probe aborted")
        }
        val descriptor = catalog.descriptors.single { it.id == "EMULATOR_HARDWARE_INDICATORS" }
        val results = EvidenceAdapterRegistry.map(
            EvidenceAdapterInput(descriptor, DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE, payload),
        ).associateBy { it.descriptor.id }

        results.values.forEach { unit ->
            assertEquals(unit.descriptor.id, EvidenceUnitCollectionStatus.PARTIAL, unit.collectionStatus)
            val shared = unit.issues.single { it.code.endsWith(".collectionErrors.shared") }
            // Entries keep their payload index, so 1 is gpu_counter and 0 (egl) is absent.
            assertEquals("gpu_counter", shared.attributes["1.source"])
            assertFalse(shared.attributes.containsKey("0.source"))
            assertTrue(unit.issues.any { it.code.endsWith(".collectionError.shared") })
        }
        assertEquals(
            listOf(
                "EMULATOR_HARDWARE_INDICATORS.egl-renderer.collectionError.shared",
                "EMULATOR_HARDWARE_INDICATORS.egl-renderer.collectionErrors",
                "EMULATOR_HARDWARE_INDICATORS.egl-renderer.collectionErrors.shared",
            ),
            results.getValue("emulator-hardware.egl-renderer").issues.map { it.code },
        )
    }

    @Test
    fun singleUnitDetectorIssueCodesCarryNoSharedSuffix() {
        val descriptor = catalog.descriptors.single { it.id == "MEMORY_FD_ANOMALY" }
        val unit = mapWithErrors(
            "MEMORY_FD_ANOMALY",
            DetectionOutcome.NOT_OBSERVED,
            collectionError("source" to "/proc/self/fd"),
        ).single()
        val localId = descriptor.evidenceUnits.single().id.substringAfter('.')

        assertEquals(listOf("MEMORY_FD_ANOMALY.$localId.collectionErrors"), unit.issues.map { it.code })
    }

    @Test
    fun anInconclusiveDetectorStillMarksUnitsItsIssuesDoNotName() {
        // Attribution narrows which unit an issue belongs to; it does not let a sibling unit
        // read as COMPLETE when the detector itself could not conclude.
        val results = mapWithErrors(
            "EMULATOR_HARDWARE_INDICATORS",
            DetectionOutcome.INCONCLUSIVE,
            collectionError("source" to "egl"),
        ).associateBy { it.descriptor.id }

        assertEquals(
            listOf("EMULATOR_HARDWARE_INDICATORS.egl-renderer.collectionErrors"),
            results.getValue("emulator-hardware.egl-renderer").issues.map { it.code },
        )
        assertEquals(
            listOf("EMULATOR_HARDWARE_INDICATORS.sched-jitter.inconclusive"),
            results.getValue("emulator-hardware.sched-jitter").issues.map { it.code },
        )
    }

    @Test
    fun everyIssueRouteValueIsEmittedByNativeCode() {
        // A route whose value native never emits is dead: its entries silently fall back to
        // shared. Fail instead, the same way an undeclared UnitPlan key once went unnoticed.
        val nativeLiterals = sourceTree("src/main/cpp")
            .filter { it.extension in setOf("cpp", "h") }
            .flatMap { file -> Regex("\"([^\"\\\\]*)\"").findAll(file.readText()).map { it.groupValues[1] } }
            .toSet()
        val routeValues = sourceTree("src/main/java/io/leemikepop/tamperprobe/lab/internal/evidence/adapters")
            .flatMap { file ->
                Regex("IssueRoute\\(\\s*\"(\\w+)\",\\s*setOf\\(([^)]*)\\)").findAll(file.readText())
                    .flatMap { route ->
                        val field = route.groupValues[1]
                        val values = Regex("\"([^\"]+)\"").findAll(route.groupValues[2]).map { it.groupValues[1] }
                        values.map { "${file.name}: $field=$it" to listOf(field, it) }
                    }
            }
            .toList()

        assertTrue("no IssueRoute declarations were found", routeValues.size >= 20)
        routeValues.forEach { (label, literals) ->
            assertTrue("$label is not emitted by native code", literals.all { it in nativeLiterals })
        }
    }

    @Test
    fun anAbsentTargetNegativeIsPublishedAsAConcealableRecord() {
        // A clean phone answers the SELinux policy oracle only through absent target types,
        // which hiding tools can manufacture. NOT_OBSERVED must say so record by record.
        listOf(
            "LSPOSED_SEPOLICY" to listOf("lsposed_file_read", "xposed_data_read"),
            "NATIVE_ROOT_SEPOLICY" to listOf("magisk_binder_call", "ksu_file_read", "adbd_adbroot_binder_call"),
        ).forEach { (detectorId, ruleIds) ->
            val descriptor = catalog.descriptors.single { it.id == detectorId }
            val units = mapPolicyOracle(detectorId, DetectionOutcome.NOT_OBSERVED, ruleIds)
            val result = DetectorResult(descriptor, DetectionOutcome.NOT_OBSERVED, EvidenceStrength.NONE, units)
            val unit = result.unitResults.single()
            val concealable = unit.records.filter { it.code == "$detectorId.policy-oracle.concealable-negative" }

            assertEquals(EvidenceUnitCollectionStatus.COMPLETE, unit.collectionStatus)
            assertFalse(unit.records.any { it.kind == EvidenceRecordKind.SIGNAL })
            assertEquals(ruleIds, concealable.map { it.attributes.getValue("ruleId") })
            concealable.forEach { record ->
                assertEquals(EvidenceRecordKind.OBSERVATION, record.kind)
                assertEquals("absent", record.attributes["targetContextState"])
                assertEquals("true", record.attributes["concealable"])
            }
        }
    }

    @Test
    fun concealableNegativesArePublishedOnlyForANotObservedResult() {
        listOf(DetectionOutcome.INCONCLUSIVE, DetectionOutcome.OBSERVED).forEach { outcome ->
            val strength = if (outcome == DetectionOutcome.OBSERVED) EvidenceStrength.WEAK else EvidenceStrength.NONE
            val units = mapPolicyOracle("LSPOSED_SEPOLICY", outcome, listOf("lsposed_file_read"), strength)

            assertFalse(
                "$outcome published a concealable negative",
                units.flatMap { it.records }.any { it.code.endsWith(".concealable-negative") },
            )
        }
    }

    private fun mapPolicyOracle(
        detectorId: String,
        outcome: DetectionOutcome,
        absentRuleIds: List<String>,
        strength: EvidenceStrength = EvidenceStrength.NONE,
    ): List<EvidenceUnitResult> {
        val descriptor = catalog.descriptors.single { it.id == detectorId }
        val payload = buildJsonObject {
            fixtures.getValue(detectorId).jsonObject.forEach { (key, value) ->
                if (key !in setOf("findings", "collectionErrors") || outcome == DetectionOutcome.OBSERVED) {
                    put(key, value)
                }
            }
            if (outcome != DetectionOutcome.OBSERVED) put("findings", buildJsonArray {})
            put("collectionErrors", buildJsonArray {})
            put("concealableNegatives", buildJsonArray {
                absentRuleIds.forEach { ruleId ->
                    add(buildJsonObject {
                        put("ruleId", ruleId)
                        put("targetContext", "u:object_r:fixture:s0")
                        put("targetContextState", "absent")
                        put("concealable", true)
                        put("trustedTier", "untrusted")
                    })
                }
            })
        }
        return EvidenceAdapterRegistry.map(EvidenceAdapterInput(descriptor, outcome, strength, payload))
    }

    private fun mapDangerousProps(
        outcome: DetectionOutcome,
        strength: EvidenceStrength,
        findingIds: List<String>,
    ): List<EvidenceUnitResult> {
        val descriptor = catalog.descriptors.single { it.id == "DANGEROUS_PROPS" }
        val payload = buildJsonObject {
            fixtures.getValue("DANGEROUS_PROPS").jsonObject.forEach { (key, value) ->
                if (key !in setOf("findings", "collectionErrors")) put(key, value)
            }
            put("findings", buildJsonArray {
                findingIds.forEach { id ->
                    add(buildJsonObject {
                        put("id", id)
                        put("property", if (id == "adb_enabled_nonstandard") "adb_enabled" else "ro.debuggable")
                        put("actual", if (id == "adb_enabled_nonstandard") "3" else "1")
                        put("strength", "weak")
                    })
                }
            })
            put("collectionErrors", buildJsonArray {})
        }
        return EvidenceAdapterRegistry.map(EvidenceAdapterInput(descriptor, outcome, strength, payload))
    }

    private fun mapWithErrors(
        detectorId: String,
        outcome: DetectionOutcome,
        vararg errors: JsonObject,
    ): List<EvidenceUnitResult> {
        val descriptor = catalog.descriptors.single { it.id == detectorId }
        val payload = buildJsonObject {
            fixtures.getValue(detectorId).jsonObject.forEach { (key, value) ->
                if (key != "collectionErrors") put(key, value)
            }
            put("collectionErrors", buildJsonArray { errors.forEach { add(it) } })
        }
        return EvidenceAdapterRegistry.map(EvidenceAdapterInput(descriptor, outcome, EvidenceStrength.NONE, payload))
    }

    private fun collectionError(vararg fields: Pair<String, String>) = buildJsonObject {
        fields.forEach { (key, value) -> put(key, value) }
        put("message", "fixture collection error")
    }

    private fun sourceTree(relative: String): Sequence<File> =
        requireNotNull(listOf(File(relative), File("tamperprobe/$relative")).firstOrNull(File::isDirectory))
            .walkTopDown()
            .filter(File::isFile)

    private fun catalogText(): String {
        val candidates = listOf(
            File("scripts/generated/detections_manifest.json"),
            File("tamperprobe/scripts/generated/detections_manifest.json"),
        )
        return requireNotNull(candidates.firstOrNull(File::isFile)).readText()
    }

    private fun fixtureText(): String {
        val candidates = listOf(
            File("src/test/resources/payload-fixtures.json"),
            File("tamperprobe/src/test/resources/payload-fixtures.json"),
        )
        return requireNotNull(candidates.firstOrNull(File::isFile)).readText()
    }

    private fun payloadFor(detectorId: String, outcome: DetectionOutcome): JsonObject {
        if (detectorId != "DANGEROUS_PACKAGES" || outcome == DetectionOutcome.OBSERVED) {
            return fixtures.getValue(detectorId).jsonObject
        }
        val unavailable = outcome == DetectionOutcome.INCONCLUSIVE
        return buildJsonObject {
            put("packageIdentity", buildJsonObject {
                put("targetCount", 1)
                put("completedQueryCount", if (unavailable) 0 else 1)
                put("detectedPackages", buildJsonArray {})
                put("issues", buildJsonArray {
                    if (unavailable) add(issue("package-manager-unavailable"))
                })
            })
            put("appDataPath", buildJsonObject {
                put("attemptedPathCount", 2)
                put("completedPathCount", if (unavailable) 0 else 2)
                put("notFoundPathCount", if (unavailable) 0 else 2)
                put("foundPaths", buildJsonArray {})
                put("inaccessiblePaths", buildJsonArray {})
                put("issues", buildJsonArray {
                    if (unavailable) add(issue("path-probe-failed"))
                })
            })
        }
    }

    private fun issue(code: String) = buildJsonObject {
        put("code", code)
        put("message", "fixture collection issue")
        put("attributes", buildJsonObject {})
    }
}
