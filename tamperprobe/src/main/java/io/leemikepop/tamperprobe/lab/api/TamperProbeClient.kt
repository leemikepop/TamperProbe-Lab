package io.leemikepop.tamperprobe.lab.api

import androidx.annotation.WorkerThread

public interface TamperProbeClient {
    public suspend fun scan(request: ScanRequest = ScanRequest()): TamperProbeReport

    @WorkerThread
    public fun scanBlocking(request: ScanRequest = ScanRequest()): TamperProbeReport

    public fun availableDetectors(): List<DetectorDescriptor>

    public fun availableEvidenceDomains(): List<EvidenceDomainDescriptor>

    public fun installAttestationStatus(statusJson: ByteArray)
}

public class TamperProbeException(
    public val code: String,
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)
