package io.leemikepop.tamperprobe.lab.presentation.mapper

import io.leemikepop.tamperprobe.lab.api.DetectorResult
import io.leemikepop.tamperprobe.lab.api.EvidenceDomainDescriptor
import io.leemikepop.tamperprobe.lab.api.EvidenceRecord
import io.leemikepop.tamperprobe.lab.api.EvidenceRecordKind
import io.leemikepop.tamperprobe.lab.presentation.model.DetectionCardUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.DetectionDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.DetailValueUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.DetectorCollectionErrorUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceDomainTagUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceIssueDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceRecordDetailUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.EvidenceUnitDetailUiModel

object DetectionUiMapper {
    fun map(
        result: DetectorResult,
        evidenceDomains: List<EvidenceDomainDescriptor>,
    ): DetectionCardUiModel {
        val descriptor = result.descriptor
        val domainById = evidenceDomains.associateBy(EvidenceDomainDescriptor::id)
        val directDomainIds = descriptor.evidenceUnits.map { it.domainId }.toSet()
        val domainTags = evidenceDomains
            .filter { it.id in directDomainIds }
            .map { domain ->
                EvidenceDomainTagUiModel(
                    id = domain.id,
                    title = domain.title,
                    shortTitle = domain.shortTitle,
                    isPrimary = domain.id == descriptor.primaryEvidenceDomainId,
                )
            }

        return DetectionCardUiModel(
            id = descriptor.id,
            title = descriptor.name,
            description = descriptor.description,
            primaryEvidenceDomainId = descriptor.primaryEvidenceDomainId,
            evidenceDomainTags = domainTags,
            outcome = result.outcome,
            evidenceStrength = result.strength,
            detail = DetectionDetailUiModel(
                id = descriptor.id,
                title = descriptor.name,
                description = descriptor.description,
                outcome = result.outcome,
                evidenceStrength = result.strength,
                payloadSchemaVersion = descriptor.payloadSchemaVersion,
                primaryEvidenceDomainTitle = domainTitle(
                    descriptor.primaryEvidenceDomainId,
                    domainById,
                ),
                evidenceDomainTags = domainTags,
                collectionError = result.collectionError?.let { error ->
                    DetectorCollectionErrorUiModel(
                        code = error.code,
                        message = error.message,
                        recoverable = error.recoverable,
                    )
                },
                units = buildUnits(result, domainById),
            ),
        )
    }

    fun mapAll(
        results: List<DetectorResult>,
        evidenceDomains: List<EvidenceDomainDescriptor>,
    ): List<DetectionCardUiModel> {
        val domainOrder = evidenceDomains.mapIndexed { index, domain -> domain.id to index }.toMap()
        return results
            .map { map(it, evidenceDomains) }
            .sortedWith(
                compareBy<DetectionCardUiModel> {
                    domainOrder[it.primaryEvidenceDomainId] ?: Int.MAX_VALUE
                }.thenBy { it.id },
            )
    }

    fun filterByEvidenceDomain(
        cards: List<DetectionCardUiModel>,
        domainId: String?,
    ): List<DetectionCardUiModel> = if (domainId == null) {
        cards
    } else {
        cards.filter { card -> card.evidenceDomainTags.any { it.id == domainId } }
    }

    private fun buildUnits(
        result: DetectorResult,
        domainById: Map<String, EvidenceDomainDescriptor>,
    ): List<EvidenceUnitDetailUiModel> = result.unitResults.map { unitResult ->
        val unit = unitResult.descriptor
        val domain = domainById[unit.domainId]
        val recordsByKind = unitResult.records.groupBy(EvidenceRecord::kind)
        val issues = unitResult.issues.map { issue ->
            EvidenceIssueDetailUiModel(
                code = issue.code,
                message = issue.message,
                attributes = attributeValues(issue.attributes),
                attributeTree = AttributeTreeBuilder.build(issue.attributes),
            )
        }
        val signals = recordsByKind[EvidenceRecordKind.SIGNAL].orEmpty().map(::recordDetail)

        EvidenceUnitDetailUiModel(
            id = unit.id,
            title = unit.title,
            domainId = unit.domainId,
            domainTitle = domain?.title ?: unit.domainId,
            domainShortTitle = domain?.shortTitle ?: unit.domainId,
            collectionStatus = unitResult.collectionStatus,
            observedObject = unit.observedObject,
            proposition = unit.proposition,
            observationChannel = unit.observationChannel,
            availability = unit.availability,
            trustBoundary = unit.trustBoundary,
            inferenceLimit = unit.inferenceLimit,
            signals = signals,
            observations = recordsByKind[EvidenceRecordKind.OBSERVATION].orEmpty()
                .map(::recordDetail),
            researchRecords = recordsByKind[EvidenceRecordKind.RESEARCH].orEmpty()
                .map(::recordDetail),
            issues = issues,
            initiallyExpanded = signals.isNotEmpty() ||
                issues.isNotEmpty() ||
                result.unitResults.size == 1,
        )
    }

    private fun recordDetail(record: EvidenceRecord): EvidenceRecordDetailUiModel =
        EvidenceRecordDetailUiModel(
            code = record.code,
            kind = record.kind,
            summary = record.summary,
            signalStrength = record.signalStrength,
            attributes = attributeValues(record.attributes),
            attributeTree = AttributeTreeBuilder.build(record.attributes),
        )

    private fun attributeValues(attributes: Map<String, String>): List<DetailValueUiModel> =
        attributes.entries.sortedBy { it.key }.map { (key, value) ->
            DetailValueUiModel(
                label = formatKey(key),
                value = value.ifBlank { "Empty" },
                isMonospace = shouldUseMonospace(value),
            )
        }

    private fun domainTitle(
        domainId: String,
        domainById: Map<String, EvidenceDomainDescriptor>,
    ): String = domainById[domainId]?.title ?: domainId

    private fun formatKey(value: String): String = AttributeTreeBuilder.formatKey(value)

    private fun shouldUseMonospace(value: String): Boolean =
        AttributeTreeBuilder.shouldUseMonospace(value)
}
