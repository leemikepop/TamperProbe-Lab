package io.leemikepop.tamperprobe.lab.internal

import android.content.Context
import android.os.SystemClock
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.DetectorDescriptor
import io.leemikepop.tamperprobe.lab.api.EvidenceDomainDescriptor
import io.leemikepop.tamperprobe.lab.api.TamperProbeException
import io.leemikepop.tamperprobe.lab.api.TamperProbeClient
import io.leemikepop.tamperprobe.lab.api.TamperProbeReport
import io.leemikepop.tamperprobe.lab.api.ScanCompletion
import io.leemikepop.tamperprobe.lab.api.ScanRequest
import io.leemikepop.tamperprobe.lab.lib.core.NativeBridge
import io.leemikepop.tamperprobe.lab.internal.fdforensics.ZygiskFdForensicsCarrierManager
import io.leemikepop.tamperprobe.lab.internal.policyoracle.SelinuxPolicyOracleCarrierManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal class TamperProbeClientImpl(
    private val context: Context,
) : TamperProbeClient {
    private val catalog: ParsedCatalog by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        CatalogLoader.load(context)
    }
    private val attestationStatusStore = AttestationStatusStore(context)

    override suspend fun scan(request: ScanRequest): TamperProbeReport =
        withContext(Dispatchers.IO) { scanBlocking(request) }

    override fun scanBlocking(request: ScanRequest): TamperProbeReport = scanLock.withLock {
        val selected = DetectorSelectionResolver.resolve(catalog, request)
        TamperProbeLog.info(
            component = COMPONENT,
            event = "scan_start",
            details = "selectedCount=${selected.size} detectorIds=${selected.joinToString(",") { it.id }}",
        )
        attestationStatusStore.ensureBundledSnapshot()
        val policyOracleSnapshot = if (selected.any { it.id in POLICY_ORACLE_DETECTOR_IDS }) {
            SelinuxPolicyOracleCarrierManager.collect(context).also { snapshot ->
                TamperProbeLog.info(
                    component = COMPONENT,
                    event = "policy_oracle_carrier_complete",
                    details = "payloadBytes=${snapshot.size}",
                )
            }
        } else {
            ByteArray(0)
        }
        val fdForensicsSnapshot = if (selected.any { it.id in FD_FORENSICS_DETECTOR_IDS }) {
            ZygiskFdForensicsCarrierManager.collect(context).also { snapshot ->
                TamperProbeLog.info(
                    component = COMPONENT,
                    event = "fd_forensics_carrier_complete",
                    details = "payloadBytes=${snapshot.size}",
                )
            }
        } else {
            ByteArray(0)
        }
        val startedAt = SystemClock.elapsedRealtime()
        val response = try {
            NativeBridge.performScan(
                context = context,
                filesDir = context.filesDir.absolutePath,
                detectorIds = selected.map { it.id }.toTypedArray(),
                policyOracleSnapshot = policyOracleSnapshot,
                fdForensicsSnapshot = fdForensicsSnapshot,
            )
        } catch (error: Throwable) {
            TamperProbeLog.error(COMPONENT, "native_invoke_failed", error = error)
            throw TamperProbeException("NATIVE_ENGINE_UNAVAILABLE", "Unable to invoke native detector engine", error)
        }
        val durationMillis = SystemClock.elapsedRealtime() - startedAt
        val envelope = WireParser.parse(response)

        if (envelope.completion == "FAILED") {
            val error = envelope.engineError
            TamperProbeLog.error(
                COMPONENT,
                "native_engine_failed",
                "code=${error?.code ?: "NATIVE_ENGINE_FAILED"}",
            )
            throw TamperProbeException(
                code = error?.code ?: "NATIVE_ENGINE_FAILED",
                message = error?.message ?: "Native detector engine failed",
            )
        }
        if (envelope.catalogVersion != catalog.catalogVersion) {
            throw TamperProbeException(
                "CATALOG_VERSION_MISMATCH",
                "Native catalog ${envelope.catalogVersion} does not match SDK catalog ${catalog.catalogVersion}",
            )
        }

        val selectedById = selected.associateBy { it.id }
        val wireById = envelope.results.associateBy { it.detectorId }
        if (wireById.keys != selectedById.keys) {
            throw TamperProbeException(
                "INCOMPLETE_WIRE_RESULTS",
                "Native result IDs do not match the requested detector selection",
            )
        }

        val results = selected.map { descriptor ->
            DetectorResultMapper.map(descriptor, wireById.getValue(descriptor.id))
        }
        results.forEach { result ->
            TamperProbeLog.info(
                component = COMPONENT,
                event = "detector_result",
                details = "detectorId=${result.descriptor.id} outcome=${result.outcome} " +
                    "strength=${result.strength} unitCount=${result.unitResults.size} " +
                    "collectionError=${result.collectionError?.code ?: "none"}",
            )
        }
        val completion = if (
            envelope.completion == "PARTIAL" || results.any { it.outcome == DetectionOutcome.FAILED }
        ) {
            ScanCompletion.PARTIAL
        } else {
            ScanCompletion.COMPLETE
        }

        TamperProbeReport(
            wireSchemaVersion = envelope.schemaVersion,
            engineVersion = envelope.engineVersion,
            catalogVersion = envelope.catalogVersion,
            completion = completion,
            durationMillis = durationMillis,
            results = results,
        ).also { report ->
            TamperProbeLog.info(
                component = COMPONENT,
                event = "scan_complete",
                details = "completion=${report.completion} durationMs=${report.durationMillis} " +
                    "resultCount=${report.results.size} observedCount=${report.results.count { it.outcome == DetectionOutcome.OBSERVED }}",
            )
        }
    }

    override fun availableDetectors(): List<DetectorDescriptor> = catalog.descriptors

    override fun availableEvidenceDomains(): List<EvidenceDomainDescriptor> = catalog.evidenceDomains

    override fun installAttestationStatus(statusJson: ByteArray) {
        attestationStatusStore.install(statusJson)
    }

    private companion object {
        const val COMPONENT = "Core"
        val POLICY_ORACLE_DETECTOR_IDS = setOf(
            "LSPOSED_SEPOLICY",
            "NATIVE_ROOT_SEPOLICY",
        )
        val FD_FORENSICS_DETECTOR_IDS = setOf(
            "ZYGISK_FD_FORENSICS",
        )
        val scanLock = ReentrantLock()
    }
}
