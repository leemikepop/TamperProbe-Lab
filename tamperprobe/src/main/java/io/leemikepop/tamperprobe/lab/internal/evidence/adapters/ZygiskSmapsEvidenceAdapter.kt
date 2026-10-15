package io.leemikepop.tamperprobe.lab.internal.evidence.adapters

import io.leemikepop.tamperprobe.lab.internal.ConfiguredEvidenceAdapter
import io.leemikepop.tamperprobe.lab.internal.DetectorEvidenceAdapter

internal object ZygiskSmapsEvidenceAdapter : DetectorEvidenceAdapter by ConfiguredEvidenceAdapter()
