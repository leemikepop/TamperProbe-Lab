package io.leemikepop.tamperprobe.lab.presentation.viewmodel

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.leemikepop.tamperprobe.lab.AppLog
import io.leemikepop.tamperprobe.lab.TamperProbe
import io.leemikepop.tamperprobe.lab.api.DetectionOutcome
import io.leemikepop.tamperprobe.lab.api.EvidenceDomainDescriptor
import io.leemikepop.tamperprobe.lab.api.ScanRequest
import io.leemikepop.tamperprobe.lab.presentation.export.ExportDocument
import io.leemikepop.tamperprobe.lab.presentation.export.LatestScanExportStore
import io.leemikepop.tamperprobe.lab.presentation.export.ScanExportProvenanceProvider
import io.leemikepop.tamperprobe.lab.presentation.export.ScanExportSnapshot
import io.leemikepop.tamperprobe.lab.presentation.export.ScanReportJsonEncoder
import io.leemikepop.tamperprobe.lab.presentation.mapper.DetectionUiMapper
import io.leemikepop.tamperprobe.lab.presentation.model.DetectionCardUiModel
import java.time.Instant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class TamperProbeViewModel(app: Application) : AndroidViewModel(app) {
    companion object {
        private const val COMPONENT = "App.TamperProbeViewModel"
    }

    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()
    private val _events = MutableSharedFlow<UiEvent>(extraBufferCapacity = 1)
    internal val events: SharedFlow<UiEvent> = _events.asSharedFlow()
    private val client = TamperProbe.create(app.applicationContext)
    private val exportStore = LatestScanExportStore()
    private val pendingExportLock = Any()
    private var pendingExport: ExportDocument? = null

    init {
        scanAllDetectors()
    }

    fun scanAllDetectors() {
        viewModelScope.launch(Dispatchers.IO) {
            AppLog.info(COMPONENT, "scan_requested")
            exportStore.onScanStarted()
            _uiState.update {
                it.copy(
                    isLoading = true,
                    canExport = false,
                    error = null,
                )
            }
            val startedAtUtc = Instant.now()
            try {
                val detectorIds = client.availableDetectors()
                    .mapTo(linkedSetOf()) { it.id }
                val evidenceDomains = client.availableEvidenceDomains()
                val requestedDetectorIds = detectorIds.toList()
                val provenance = ScanExportProvenanceProvider.capture()
                val report = client.scan(ScanRequest(detectorIds))
                val completedAtUtc = Instant.now()
                val results = report.results

                AppLog.info(
                    COMPONENT,
                    "scan_complete",
                    "completion=${report.completion} durationMs=${report.durationMillis} " +
                        "selectedCount=${detectorIds.size} resultCount=${results.size}",
                )
                results.forEach { result ->
                    AppLog.debug(
                        COMPONENT,
                        "detector_presented",
                        "detectorId=${result.descriptor.id} outcome=${result.outcome} strength=${result.strength}",
                    )
                }

                val cards = DetectionUiMapper.mapAll(results, evidenceDomains)
                val observedCount = cards.count { it.outcome == DetectionOutcome.OBSERVED }
                val hasObservedResults = observedCount > 0
                exportStore.onScanSucceeded(
                    ScanExportSnapshot(
                        startedAtUtc = startedAtUtc,
                        completedAtUtc = completedAtUtc,
                        requestedDetectorIds = requestedDetectorIds,
                        report = report,
                        provenance = provenance,
                    ),
                )

                _uiState.update {
                    it.copy(
                        isLoading = false,
                        cards = cards,
                        evidenceDomains = evidenceDomains,
                        hasObservedResults = hasObservedResults,
                        observedCount = observedCount,
                        resultCount = cards.size,
                        scanDurationMillis = report.durationMillis,
                        canExport = exportStore.canExport(),
                    )
                }
            } catch (e: Exception) {
                exportStore.onScanFailed()
                AppLog.error(COMPONENT, "scan_failed", error = e)
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        canExport = exportStore.canExport(),
                        error = e.message ?: "未知錯誤",
                    )
                }
            }
        }
    }

    fun prepareExport() {
        val snapshot = exportStore.snapshotForExport() ?: return
        _uiState.update { it.copy(isExporting = true) }
        viewModelScope.launch(Dispatchers.Default) {
            try {
                val document = ScanReportJsonEncoder.createDocument(
                    snapshot = snapshot,
                    exportedAtUtc = Instant.now(),
                )
                synchronized(pendingExportLock) {
                    pendingExport = document
                }
                _events.emit(UiEvent.LaunchExport(document.fileName))
            } catch (e: Exception) {
                AppLog.error(COMPONENT, "report_export_prepare_failed", error = e)
                _uiState.update { it.copy(isExporting = false) }
                _events.emit(UiEvent.ShowMessage("Unable to prepare report export"))
            }
        }
    }

    fun cancelPendingExport() {
        synchronized(pendingExportLock) {
            pendingExport = null
        }
        _uiState.update { it.copy(isExporting = false) }
    }

    fun writePendingExport(uri: Uri) {
        val document = synchronized(pendingExportLock) {
            pendingExport.also { pendingExport = null }
        } ?: run {
            _uiState.update { it.copy(isExporting = false) }
            return
        }

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val output = getApplication<Application>()
                    .contentResolver
                    .openOutputStream(uri, "wt")
                    ?: error("The selected document provider did not open an output stream")
                output.use {
                    it.write(document.bytes)
                    it.flush()
                }
                AppLog.info(
                    COMPONENT,
                    "report_exported",
                    "byteCount=${document.bytes.size}",
                )
                _events.emit(UiEvent.ShowMessage("Report exported"))
            } catch (e: Exception) {
                AppLog.error(COMPONENT, "report_export_failed", error = e)
                _events.emit(UiEvent.ShowMessage("Unable to export report"))
            } finally {
                _uiState.update { it.copy(isExporting = false) }
            }
        }
    }

    fun selectEvidenceDomain(domainId: String?) {
        _uiState.update { state ->
            state.copy(selectedEvidenceDomainId = domainId)
        }
    }

    fun clearResults() {
        exportStore.clear()
        synchronized(pendingExportLock) {
            pendingExport = null
        }
        _uiState.value = UiState()
    }

    internal sealed interface UiEvent {
        data class LaunchExport(val fileName: String) : UiEvent
        data class ShowMessage(val message: String) : UiEvent
    }

    /**
     * UI 狀態資料類別
     */
    data class UiState(
        val isLoading: Boolean = false,
        val cards: List<DetectionCardUiModel> = emptyList(),
        val evidenceDomains: List<EvidenceDomainDescriptor> = emptyList(),
        val selectedEvidenceDomainId: String? = null,
        val hasObservedResults: Boolean = false,
        val observedCount: Int = 0,
        val resultCount: Int = 0,
        val scanDurationMillis: Long? = null,
        val canExport: Boolean = false,
        val isExporting: Boolean = false,
        val error: String? = null,
    )
}
