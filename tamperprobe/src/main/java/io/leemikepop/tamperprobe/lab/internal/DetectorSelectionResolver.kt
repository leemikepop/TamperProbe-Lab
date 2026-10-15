package io.leemikepop.tamperprobe.lab.internal

import io.leemikepop.tamperprobe.lab.api.DetectorDescriptor
import io.leemikepop.tamperprobe.lab.api.TamperProbeException
import io.leemikepop.tamperprobe.lab.api.ScanRequest

internal object DetectorSelectionResolver {
    fun resolve(catalog: ParsedCatalog, request: ScanRequest): List<DetectorDescriptor> {
        val requestedIds = request.detectorIds
        if (requestedIds != null) {
            if (requestedIds.isEmpty()) {
                throw TamperProbeException("EMPTY_SELECTION", "At least one detector ID is required")
            }
            val descriptorsById = catalog.descriptors.associateBy { it.id }
            val unknown = requestedIds - descriptorsById.keys
            if (unknown.isNotEmpty()) {
                throw TamperProbeException("UNKNOWN_DETECTOR", "Unknown detector IDs: ${unknown.sorted()}")
            }
            return requestedIds.map { descriptorsById.getValue(it) }.sortedBy { it.id }
        }

        // The research edition has no maturity tiers or default selection: every detector runs.
        return catalog.descriptors.sortedBy { it.id }
    }
}
