package io.leemikepop.tamperprobe.lab.internal

import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.BuildPatchCoherenceEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.BusyboxEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.CustomRomEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.DangerousPackagesEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.DangerousPropsEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.DrmCredentialCoherenceEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.ElfTextIntegrityEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.EmulatorHardwareIndicatorsEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.EmulatorSystemProfileEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.KernelCheckEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.KeystoreGrantSplitEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.LsposedMapsEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.LsposedSepolicyEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.MemoryFdAnomalyEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.MemoryLinkerVisibilityEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.MemoryMapsAnomalyEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.MountIntegrityEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.NativeRootDevptsEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.NativeRootPathsEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.NativeRootPrctlEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.NativeRootSepolicyEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.NativeRootSusfsEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.PackageStorageVisibilityEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.PrologueScannerEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.PropertyAreaResidueEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.RuntimeInstrumentationEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.RwPathsEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.SelinuxCheckEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.SuBinaryEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.SuContextEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.SystemPropertiesTamperEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.TeeAttestationEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.TeeKeystoreConsistencyEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.TeeOversizedChallengeEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.VdsoIntegrityEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.ZygiskFdForensicsEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.ZygiskNamespaceEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.evidence.adapters.ZygiskSmapsEvidenceAdapter
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.DetectorDescriptor
import io.leemikepop.tamperprobe.lab.api.EvidenceIssue
import io.leemikepop.tamperprobe.lab.api.EvidenceRecord
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.api.EvidenceStrength
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitCollectionStatus
import io.leemikepop.tamperprobe.lab.api.EvidenceUnitResult
import io.leemikepop.tamperprobe.lab.lib.core.models.DetectionPayload
import io.leemikepop.tamperprobe.lab.lib.detections.appvisibility.DangerousPackagesPayload
import io.leemikepop.tamperprobe.lab.lib.detections.appvisibility.PackageStorageVisibilityPayload
import io.leemikepop.tamperprobe.lab.lib.detections.binaryartifact.BusyBoxPayload
import io.leemikepop.tamperprobe.lab.lib.detections.binaryartifact.SuBinaryPayload
import io.leemikepop.tamperprobe.lab.lib.detections.filesystemstate.MountIntegrityPayload
import io.leemikepop.tamperprobe.lab.lib.detections.filesystemstate.NativeRootPathsPayload
import io.leemikepop.tamperprobe.lab.lib.detections.filesystemstate.RwPathsPayload
import io.leemikepop.tamperprobe.lab.lib.detections.hardwareattestation.DrmCredentialCoherencePayload
import io.leemikepop.tamperprobe.lab.lib.detections.hardwareattestation.KeystoreGrantSplitPayload
import io.leemikepop.tamperprobe.lab.lib.detections.hardwareattestation.TeeAttestationPayload
import io.leemikepop.tamperprobe.lab.lib.detections.hardwareattestation.TeeKeystoreConsistencyPayload
import io.leemikepop.tamperprobe.lab.lib.detections.hardwareattestation.TeeOversizedChallengePayload
import io.leemikepop.tamperprobe.lab.lib.detections.kernelinterface.KernelCheckPayload
import io.leemikepop.tamperprobe.lab.lib.detections.kernelinterface.LsposedSepolicyPayload
import io.leemikepop.tamperprobe.lab.lib.detections.kernelinterface.NativeRootDevptsPayload
import io.leemikepop.tamperprobe.lab.lib.detections.kernelinterface.NativeRootPrctlPayload
import io.leemikepop.tamperprobe.lab.lib.detections.kernelinterface.NativeRootSepolicyPayload
import io.leemikepop.tamperprobe.lab.lib.detections.kernelinterface.NativeRootSusfsPayload
import io.leemikepop.tamperprobe.lab.lib.detections.processmemory.MemoryFdPayload
import io.leemikepop.tamperprobe.lab.lib.detections.processmemory.MemoryLinkerVisibilityPayload
import io.leemikepop.tamperprobe.lab.lib.detections.processmemory.MemoryMapsPayload
import io.leemikepop.tamperprobe.lab.lib.detections.processmemory.SuContextPayload
import io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity.ElfTextIntegrityPayload
import io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity.LsposedMapsPayload
import io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity.PrologueScannerPayload
import io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity.RuntimeInstrumentationPayload
import io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity.VdsoIntegrityPayload
import io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity.ZygiskFdForensicsPayload
import io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity.ZygiskNamespacePayload
import io.leemikepop.tamperprobe.lab.lib.detections.runtimeintegrity.ZygiskSmapsPayload
import io.leemikepop.tamperprobe.lab.lib.detections.systemstate.BuildPatchCoherencePayload
import io.leemikepop.tamperprobe.lab.lib.detections.systemstate.CustomRomPayload
import io.leemikepop.tamperprobe.lab.lib.detections.systemstate.DangerousPropsPayload
import io.leemikepop.tamperprobe.lab.lib.detections.systemstate.EmulatorHardwareIndicatorsPayload
import io.leemikepop.tamperprobe.lab.lib.detections.systemstate.EmulatorSystemProfilePayload
import io.leemikepop.tamperprobe.lab.lib.detections.systemstate.PropertyAreaResiduePayload
import io.leemikepop.tamperprobe.lab.lib.detections.systemstate.SelinuxCheckPayload
import io.leemikepop.tamperprobe.lab.lib.detections.systemstate.SystemPropertiesTamperPayload
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.Json

internal fun interface DetectorEvidenceAdapter {
    fun map(input: EvidenceAdapterInput): List<EvidenceUnitResult>
}

internal fun interface TypedDetectorEvidenceAdapter<P : DetectionPayload> {
    fun map(input: EvidenceAdapterInput, payload: P): List<EvidenceUnitResult>
}

internal fun interface DetectorRuntimeBinding {
    fun decodeAndMap(input: EvidenceAdapterInput): List<EvidenceUnitResult>
}

internal class EvidenceAdaptationException(
    val code: String,
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

internal data class EvidenceAdapterInput(
    val descriptor: DetectorDescriptor,
    val outcome: DetectionOutcome,
    val strength: EvidenceStrength,
    val payload: JsonObject,
)

/**
 * Claims a collection-issue entry for one unit. An entry is one JSON object inside an issue
 * array such as `collectionErrors`; it matches when its [field] holds one of [values].
 *
 * Declare a route only for a channel that feeds a strict subset of the detector's units. A
 * channel every unit depends on stays unrouted, so its entries reach every unit as a shared
 * issue - and so does any entry whose field value native renames or newly introduces. A
 * missing route therefore over-reports an issue; it can never hide one.
 */
internal data class IssueRoute(val field: String, val values: Set<String>) {
    fun matches(entry: JsonElement): Boolean =
        ((entry as? JsonObject)?.get(field) as? JsonPrimitive)?.content in values
}

internal data class UnitPlan(
    val unitId: String,
    val payloadKeys: Set<String> = emptySet(),
    val researchKeys: Set<String> = emptySet(),
    val researchOnly: Boolean = false,
    val signalMatcher: ((JsonObject) -> Boolean)? = null,
    val issueRoutes: List<IssueRoute> = emptyList(),
    /**
     * Payload array whose entries are negatives the detector could not trust, each published
     * as its own `concealable-negative` OBSERVATION record on a NOT_OBSERVED result, so a
     * reader can tell "nothing allowed" from "nothing allowed, but only because a type a
     * hiding tool can remove was absent".
     */
    val concealableNegativeKey: String? = null,
    /**
     * True when the payload says this unit's channel produced nothing it could compare. The
     * unit then publishes no record, only its issues, so it reads UNAVAILABLE instead of as a
     * negative whatever the detector outcome is.
     */
    val unavailableMatcher: ((JsonObject) -> Boolean)? = null,
)

internal class ConfiguredEvidenceAdapter(
    private val signalUnitId: String? = null,
    private val plans: List<UnitPlan> = emptyList(),
) : DetectorEvidenceAdapter {
    override fun map(input: EvidenceAdapterInput): List<EvidenceUnitResult> {
        check(input.outcome != DetectionOutcome.FAILED) { "FAILED results cannot publish unit reports" }
        val planById = plans.associateBy { it.unitId }
        val descriptorIds = input.descriptor.evidenceUnits.map { it.id }.toSet()
        if (planById.size != plans.size ||
            (plans.isEmpty() && descriptorIds.size != 1) ||
            (plans.isNotEmpty() && planById.keys != descriptorIds)
        ) {
            throw EvidenceAdaptationException(
                "EVIDENCE_UNIT_BINDING_FAILED",
                "${input.descriptor.id} adapter units do not match the catalog descriptor",
            )
        }
        val unavailableUnits = plans
            .filter { it.unavailableMatcher?.invoke(input.payload) == true }
            .mapTo(mutableSetOf()) { it.unitId }
        val dynamicallyMatchedSignalUnits = plans
            .filter { it.unitId !in unavailableUnits && it.signalMatcher?.invoke(input.payload) == true }
            .mapTo(mutableSetOf()) { it.unitId }
        val fallbackSignalUnitId = signalUnitId ?: input.descriptor.evidenceUnits
            .firstOrNull { planById[it.id]?.researchOnly != true && it.id !in unavailableUnits }
            ?.id

        return input.descriptor.evidenceUnits.map { descriptor ->
            val plan = planById[descriptor.id] ?: UnitPlan(descriptor.id)
            val localId = descriptor.id.substringAfter('.', descriptor.id)
            val recordPrefix = "${input.descriptor.id}.${normalize(localId)}"
            val issues = collectionIssues(
                recordPrefix,
                plan,
                input.payload,
                input.outcome,
                sharedSuffix = input.descriptor.evidenceUnits.size > 1,
            )
            if (descriptor.id in unavailableUnits) {
                val unavailableIssues = issues.ifEmpty {
                    listOf(
                        EvidenceIssue(
                            code = "$recordPrefix.unavailable",
                            message = "The unit's channel produced nothing this scan could compare",
                        ),
                    )
                }
                return@map EvidenceUnitResult(
                    descriptor,
                    EvidenceUnitCollectionStatus.UNAVAILABLE,
                    emptyList(),
                    unavailableIssues,
                )
            }
            val attributes = selectAttributes(input.payload, plan.payloadKeys)
            val records = mutableListOf<EvidenceRecord>()

            val contributesSignal = input.outcome == DetectionOutcome.OBSERVED && !plan.researchOnly &&
                (descriptor.id in dynamicallyMatchedSignalUnits ||
                    (dynamicallyMatchedSignalUnits.isEmpty() && descriptor.id == fallbackSignalUnitId))
            if (contributesSignal) {
                records += EvidenceRecord(
                    code = "$recordPrefix.assessment-signal",
                    kind = EvidenceRecordKind.SIGNAL,
                    summary = "${descriptor.title} contributed to the detector assessment",
                    signalStrength = input.strength,
                    attributes = attributes,
                )
            } else if (plan.researchOnly &&
                (input.outcome != DetectionOutcome.INCONCLUSIVE || attributes.isNotEmpty())
            ) {
                records += EvidenceRecord(
                    code = "$recordPrefix.research-snapshot",
                    kind = EvidenceRecordKind.RESEARCH,
                    summary = "${descriptor.title} research data was collected",
                    attributes = attributes,
                )
            } else if (input.outcome != DetectionOutcome.INCONCLUSIVE || attributes.isNotEmpty()) {
                records += EvidenceRecord(
                    code = "$recordPrefix.collection-summary",
                    kind = EvidenceRecordKind.OBSERVATION,
                    summary = "${descriptor.title} collection completed",
                    attributes = attributes,
                )
            }

            if (input.outcome == DetectionOutcome.NOT_OBSERVED) {
                plan.concealableNegativeKey?.let { key -> input.payload[key] as? JsonArray }.orEmpty()
                    .forEach { entry ->
                        records += EvidenceRecord(
                            code = "$recordPrefix.concealable-negative",
                            kind = EvidenceRecordKind.OBSERVATION,
                            summary = "${descriptor.title} negative rests on an absent target that concealment can produce",
                            attributes = flatten(entry),
                        )
                    }
            }

            val researchAttributes = selectAttributes(input.payload, plan.researchKeys)
            if (!plan.researchOnly && plan.researchKeys.isNotEmpty() && researchAttributes.isNotEmpty()) {
                records += EvidenceRecord(
                    code = "$recordPrefix.research-snapshot",
                    kind = EvidenceRecordKind.RESEARCH,
                    summary = "${descriptor.title} research data was collected",
                    attributes = researchAttributes,
                )
            }

            val status = when {
                records.isEmpty() -> EvidenceUnitCollectionStatus.UNAVAILABLE
                issues.isNotEmpty() -> EvidenceUnitCollectionStatus.PARTIAL
                else -> EvidenceUnitCollectionStatus.COMPLETE
            }
            EvidenceUnitResult(descriptor, status, records, issues)
        }
    }

    /**
     * An issue entry claimed by this unit's [UnitPlan.issueRoutes] is published as
     * `<prefix>.<key>`, and only on the units that claim it: a route asserts that the channel
     * feeds those units and no other. An entry no unit claims belongs to the detector as a
     * whole and is published on every unit; on a multi-unit detector its code gains a
     * `.shared` suffix so a reader can tell "this unit's channel failed" from "a channel the
     * units share failed". Entries keep their payload index in the attribute keys either way.
     */
    private fun collectionIssues(
        prefix: String,
        plan: UnitPlan,
        payload: JsonObject,
        outcome: DetectionOutcome,
        sharedSuffix: Boolean,
    ): List<EvidenceIssue> {
        val issues = mutableListOf<EvidenceIssue>()
        ISSUE_KEYS.forEach { key ->
            val value = payload[key]?.takeUnless(::isEmpty) ?: return@forEach
            val entries = (value as? JsonArray)?.mapIndexed { index, entry -> index.toString() to entry }
                ?: listOf("" to value)
            // Presence is tracked apart from the attributes: an entry with no scalar fields
            // flattens to nothing, and must still raise its issue.
            var hasOwned = false
            var hasShared = false
            val owned = linkedMapOf<String, String>()
            val shared = linkedMapOf<String, String>()
            entries.forEach { (index, entry) ->
                when {
                    plan.issueRoutes.any { it.matches(entry) } -> {
                        hasOwned = true
                        owned.putAll(flatten(entry, index))
                    }
                    plans.none { other -> other.issueRoutes.any { it.matches(entry) } } -> {
                        hasShared = true
                        shared.putAll(flatten(entry, index))
                    }
                }
            }
            if (hasOwned) {
                issues += EvidenceIssue(
                    code = "$prefix.$key",
                    message = "Unit collection reported $key",
                    attributes = owned,
                )
            }
            if (hasShared) {
                issues += EvidenceIssue(
                    code = if (sharedSuffix) "$prefix.$key.shared" else "$prefix.$key",
                    message = if (sharedSuffix) {
                        "Detector collection reported $key on a channel not attributed to a single unit"
                    } else {
                        "Unit collection reported $key"
                    },
                    attributes = shared,
                )
            }
        }
        if (outcome == DetectionOutcome.INCONCLUSIVE && issues.isEmpty()) {
            issues += EvidenceIssue(
                code = "$prefix.inconclusive",
                message = "The detector could not complete a conclusive observation for this unit",
            )
        }
        return issues
    }
}

internal object EvidenceAdapterRegistry {
    private val bindings: Map<String, DetectorRuntimeBinding> = mapOf(
        "BUILD_PATCH_COHERENCE" to configuredBinding(
            BuildPatchCoherencePayload.serializer(),
            BuildPatchCoherenceEvidenceAdapter,
        ),
        "BUSYBOX" to configuredBinding(BusyBoxPayload.serializer(), BusyboxEvidenceAdapter),
        "CUSTOM_ROM" to configuredBinding(CustomRomPayload.serializer(), CustomRomEvidenceAdapter),
        "DANGEROUS_PACKAGES" to typedBinding(
            DangerousPackagesPayload.serializer(),
            DangerousPackagesEvidenceAdapter,
        ),
        "DANGEROUS_PROPS" to configuredBinding(DangerousPropsPayload.serializer(), DangerousPropsEvidenceAdapter),
        "DRM_CREDENTIAL_COHERENCE" to configuredBinding(
            DrmCredentialCoherencePayload.serializer(),
            DrmCredentialCoherenceEvidenceAdapter,
        ),
        "ELF_TEXT_INTEGRITY" to configuredBinding(
            ElfTextIntegrityPayload.serializer(),
            ElfTextIntegrityEvidenceAdapter,
        ),
        "EMULATOR_HARDWARE_INDICATORS" to configuredBinding(
            EmulatorHardwareIndicatorsPayload.serializer(),
            EmulatorHardwareIndicatorsEvidenceAdapter,
        ),
        "EMULATOR_SYSTEM_PROFILE" to configuredBinding(
            EmulatorSystemProfilePayload.serializer(),
            EmulatorSystemProfileEvidenceAdapter,
        ),
        "KERNEL_CHECK" to configuredBinding(KernelCheckPayload.serializer(), KernelCheckEvidenceAdapter),
        "KEYSTORE_GRANT_SPLIT" to configuredBinding(
            KeystoreGrantSplitPayload.serializer(),
            KeystoreGrantSplitEvidenceAdapter,
        ),
        "LSPOSED_MAPS" to configuredBinding(LsposedMapsPayload.serializer(), LsposedMapsEvidenceAdapter),
        "LSPOSED_SEPOLICY" to configuredBinding(
            LsposedSepolicyPayload.serializer(),
            LsposedSepolicyEvidenceAdapter,
        ),
        "MEMORY_FD_ANOMALY" to configuredBinding(
            MemoryFdPayload.serializer(),
            MemoryFdAnomalyEvidenceAdapter,
        ),
        "MEMORY_LINKER_VISIBILITY" to configuredBinding(
            MemoryLinkerVisibilityPayload.serializer(),
            MemoryLinkerVisibilityEvidenceAdapter,
        ),
        "MEMORY_MAPS_ANOMALY" to configuredBinding(
            MemoryMapsPayload.serializer(),
            MemoryMapsAnomalyEvidenceAdapter,
        ),
        "MOUNT_INTEGRITY" to configuredBinding(MountIntegrityPayload.serializer(), MountIntegrityEvidenceAdapter),
        "NATIVE_ROOT_DEVPTS" to configuredBinding(
            NativeRootDevptsPayload.serializer(),
            NativeRootDevptsEvidenceAdapter,
        ),
        "NATIVE_ROOT_PATHS" to configuredBinding(
            NativeRootPathsPayload.serializer(),
            NativeRootPathsEvidenceAdapter,
        ),
        "NATIVE_ROOT_PRCTL" to configuredBinding(
            NativeRootPrctlPayload.serializer(),
            NativeRootPrctlEvidenceAdapter,
        ),
        "NATIVE_ROOT_SEPOLICY" to configuredBinding(
            NativeRootSepolicyPayload.serializer(),
            NativeRootSepolicyEvidenceAdapter,
        ),
        "NATIVE_ROOT_SUSFS" to configuredBinding(
            NativeRootSusfsPayload.serializer(),
            NativeRootSusfsEvidenceAdapter,
        ),
        "PACKAGE_STORAGE_VISIBILITY" to configuredBinding(
            PackageStorageVisibilityPayload.serializer(),
            PackageStorageVisibilityEvidenceAdapter,
        ),
        "PROLOGUE_SCANNER" to configuredBinding(
            PrologueScannerPayload.serializer(),
            PrologueScannerEvidenceAdapter,
        ),
        "PROPERTY_AREA_RESIDUE" to configuredBinding(
            PropertyAreaResiduePayload.serializer(),
            PropertyAreaResidueEvidenceAdapter,
        ),
        "RUNTIME_INSTRUMENTATION" to configuredBinding(
            RuntimeInstrumentationPayload.serializer(),
            RuntimeInstrumentationEvidenceAdapter,
        ),
        "RW_PATHS" to configuredBinding(RwPathsPayload.serializer(), RwPathsEvidenceAdapter),
        "SELINUX_CHECK" to configuredBinding(SelinuxCheckPayload.serializer(), SelinuxCheckEvidenceAdapter),
        "SU_BINARY" to configuredBinding(SuBinaryPayload.serializer(), SuBinaryEvidenceAdapter),
        "SU_CONTEXT" to configuredBinding(SuContextPayload.serializer(), SuContextEvidenceAdapter),
        "SYSTEM_PROPERTIES_TAMPER" to configuredBinding(
            SystemPropertiesTamperPayload.serializer(),
            SystemPropertiesTamperEvidenceAdapter,
        ),
        "TEE_ATTESTATION" to configuredBinding(TeeAttestationPayload.serializer(), TeeAttestationEvidenceAdapter),
        "TEE_KEYSTORE_CONSISTENCY" to configuredBinding(
            TeeKeystoreConsistencyPayload.serializer(),
            TeeKeystoreConsistencyEvidenceAdapter,
        ),
        "TEE_OVERSIZED_CHALLENGE" to configuredBinding(
            TeeOversizedChallengePayload.serializer(),
            TeeOversizedChallengeEvidenceAdapter,
        ),
        "VDSO_INTEGRITY" to configuredBinding(VdsoIntegrityPayload.serializer(), VdsoIntegrityEvidenceAdapter),
        "ZYGISK_FD_FORENSICS" to configuredBinding(
            ZygiskFdForensicsPayload.serializer(),
            ZygiskFdForensicsEvidenceAdapter,
        ),
        "ZYGISK_NAMESPACE" to configuredBinding(
            ZygiskNamespacePayload.serializer(),
            ZygiskNamespaceEvidenceAdapter,
        ),
        "ZYGISK_SMAPS" to configuredBinding(ZygiskSmapsPayload.serializer(), ZygiskSmapsEvidenceAdapter),
    )

    val bindingIds: Set<String>
        get() = bindings.keys

    fun map(input: EvidenceAdapterInput): List<EvidenceUnitResult> =
        requireNotNull(bindings[input.descriptor.id]) {
            "No runtime binding is registered for ${input.descriptor.id}"
        }.decodeAndMap(input)
}

private val bindingJson = Json {
    ignoreUnknownKeys = true
    isLenient = true
    encodeDefaults = true
}

private fun <P : DetectionPayload> configuredBinding(
    serializer: KSerializer<P>,
    adapter: DetectorEvidenceAdapter,
): DetectorRuntimeBinding = typedBinding(serializer) { input, _ ->
    // Decoding establishes the detector-specific payload contract. Existing configured
    // adapters retain the original JSON so omitted optional fields do not become synthetic
    // observations when serializer defaults are materialized.
    adapter.map(input)
}

private fun <P : DetectionPayload> typedBinding(
    serializer: KSerializer<P>,
    adapter: TypedDetectorEvidenceAdapter<P>,
): DetectorRuntimeBinding = typedBinding(serializer, adapter::map)

private fun <P : DetectionPayload> typedBinding(
    serializer: KSerializer<P>,
    mapper: (EvidenceAdapterInput, P) -> List<EvidenceUnitResult>,
): DetectorRuntimeBinding = DetectorRuntimeBinding { input ->
    val payload = try {
        bindingJson.decodeFromJsonElement(serializer, input.payload)
    } catch (error: SerializationException) {
        throw EvidenceAdaptationException(
            "PAYLOAD_DECODE_FAILED",
            error.message ?: "Payload decoding failed for ${input.descriptor.id}",
            error,
        )
    } catch (error: Exception) {
        throw EvidenceAdaptationException(
            "PAYLOAD_DECODE_FAILED",
            error.message ?: "Payload decoding failed for ${input.descriptor.id}",
            error,
        )
    }
    mapper(input, payload)
}

private val ISSUE_KEYS = setOf(
    "collectionWarning",
    "collectionWarnings",
    "collectionError",
    "collectionErrors",
    "warnings",
)

private fun selectAttributes(payload: JsonObject, keys: Set<String>): Map<String, String> {
    val selected = JsonObject(payload.filterKeys { key ->
        key !in ISSUE_KEYS && (keys.isEmpty() || key in keys)
    })
    return flatten(selected)
}

internal fun JsonObject.hasNonEmptyArray(key: String): Boolean =
    (this[key] as? JsonArray)?.isNotEmpty() == true

internal fun JsonObject.hasArrayObjectValue(
    key: String,
    field: String,
    values: Set<String>,
): Boolean = (this[key] as? JsonArray).orEmpty().any { element ->
    val value = (element as? JsonObject)?.get(field) as? JsonPrimitive
    value?.content in values
}

internal fun JsonObject.hasArrayObjectValueOutside(
    key: String,
    field: String,
    excludedValues: Set<String>,
): Boolean = (this[key] as? JsonArray).orEmpty().any { element ->
    val value = (element as? JsonObject)?.get(field) as? JsonPrimitive
    value != null && value.content !in excludedValues
}

private fun flatten(element: JsonElement, prefix: String = ""): Map<String, String> {
    val flattened = linkedMapOf<String, String>()
    when (element) {
        is JsonObject -> element.forEach { (key, value) ->
            val child = if (prefix.isEmpty()) key else "$prefix.$key"
            flattened.putAll(flatten(value, child))
        }
        is JsonArray -> element.forEachIndexed { index, value ->
            val child = if (prefix.isEmpty()) index.toString() else "$prefix.$index"
            flattened.putAll(flatten(value, child))
        }
        is JsonPrimitive -> flattened[prefix.ifEmpty { "value" }] = element.content
        JsonNull -> Unit
    }
    return flattened
}

private fun isEmpty(element: JsonElement): Boolean = when (element) {
    JsonNull -> true
    is JsonArray -> element.isEmpty()
    is JsonObject -> element.isEmpty()
    is JsonPrimitive -> element.content.isBlank()
}

private fun normalize(value: String): String = value
    .lowercase()
    .replace(Regex("[^a-z0-9-]+"), "-")
    .trim('-')
