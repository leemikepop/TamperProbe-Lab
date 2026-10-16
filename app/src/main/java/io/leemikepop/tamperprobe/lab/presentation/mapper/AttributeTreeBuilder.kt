package io.leemikepop.tamperprobe.lab.presentation.mapper

import io.leemikepop.tamperprobe.lab.presentation.model.AttributeNodeUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.AttributeNodeUiModel.Field
import io.leemikepop.tamperprobe.lab.presentation.model.AttributeNodeUiModel.Group
import io.leemikepop.tamperprobe.lab.presentation.model.AttributeNodeUiModel.GroupKind
import io.leemikepop.tamperprobe.lab.presentation.model.AttributeNodeUiModel.ValueList

/**
 * Regroups flattened attribute keys (`findings.0.check`, `bannerSources.1`,
 * `attestation.bootStateCoherence.claim.flashLocked`) into a display tree:
 *
 * - `x.0`, `x.1`, ... holding plain values become one [ValueList];
 * - `x.0.*`, `x.1.*`, ... become one [GroupKind.LIST] with a [GroupKind.LIST_ITEM] per index;
 * - other shared prefixes become a [GroupKind.SECTION]; single-child prefix chains are merged
 *   into one breadcrumb title (`Attestation › Boot State Coherence`).
 *
 * Every input value ends up in exactly one [Field]. Presentation only: the export encodes the
 * original report and never reads this tree.
 */
object AttributeTreeBuilder {
    const val BREADCRUMB_SEPARATOR = " › "

    fun build(attributes: Map<String, String>): List<AttributeNodeUiModel> {
        if (attributes.isEmpty()) return emptyList()
        val root = Node()
        attributes.forEach { (key, value) ->
            var node = root
            key.split('.').forEach { segment -> node = node.children.getOrPut(segment) { Node() } }
            node.value = value
        }
        // Attributes that are themselves a list (`0.source`, `1.source`) become top-level items.
        return if (root.children.keys.all(::isIndex)) listItems(root) else childrenOf(root)
    }

    fun formatKey(value: String): String = value
        .replace(Regex("([a-z0-9])([A-Z])"), "$1 $2")
        .replace('_', ' ')
        .replace('.', ' ')
        .trim()
        .replaceFirstChar { it.uppercase() }
        .ifEmpty { "(unnamed)" }

    /** Monospace is reserved for raw tokens: paths, digests, hex, identifiers and codes. */
    fun shouldUseMonospace(value: String): Boolean {
        if (value.isEmpty() || value.any(Char::isWhitespace)) return false
        return value.contains('/') ||
            value.contains('\\') ||
            value.contains(':') ||
            value.contains('_') ||
            value.startsWith("0x") ||
            (value.length >= 16 && value.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) ||
            value.length >= 24
    }

    private class Node {
        var value: String? = null
        val children = LinkedHashMap<String, Node>()
    }

    private fun childrenOf(node: Node): List<AttributeNodeUiModel> {
        val converted = node.children.entries
            .sortedWith { a, b -> compareSegments(a.key, b.key) }
            .flatMap { (segment, child) -> convert(formatKey(segment), child) }
        // Plain rows first, nested blocks after, so short facts stay at the top of each level.
        return converted.filterNot { it is Group } + converted.filterIsInstance<Group>()
    }

    private fun convert(title: String, node: Node): List<AttributeNodeUiModel> {
        val ownValue = node.value?.let { listOf(field(title, it)) }.orEmpty()
        if (node.children.isEmpty()) return ownValue

        val indexed = node.children.keys.all(::isIndex)
        val nested = when {
            indexed && node.children.values.all { it.children.isEmpty() } -> ValueList(
                label = title,
                values = sortedChildren(node).map { (segment, child) ->
                    field(indexLabel(segment), child.value.orEmpty())
                },
            )
            indexed -> Group(title = title, kind = GroupKind.LIST, children = listItems(node))
            else -> mergeChain(title, childrenOf(node))
        }
        return ownValue + nested
    }

    private fun listItems(node: Node): List<AttributeNodeUiModel> =
        sortedChildren(node).map { (segment, child) ->
            if (child.children.isEmpty()) {
                field(indexLabel(segment), child.value.orEmpty())
            } else {
                Group(
                    title = indexLabel(segment),
                    kind = GroupKind.LIST_ITEM,
                    children = child.value?.let { listOf(field(VALUE_LABEL, it)) }.orEmpty() +
                        childrenOf(child),
                )
            }
        }

    private fun mergeChain(title: String, children: List<AttributeNodeUiModel>): Group {
        val only = children.singleOrNull()
        return if (only is Group && only.kind == GroupKind.SECTION) {
            Group("$title$BREADCRUMB_SEPARATOR${only.title}", GroupKind.SECTION, only.children)
        } else {
            Group(title, GroupKind.SECTION, children)
        }
    }

    private fun sortedChildren(node: Node): List<Pair<String, Node>> = node.children.entries
        .sortedWith { a, b -> compareSegments(a.key, b.key) }
        .map { it.key to it.value }

    private fun field(label: String, value: String) = Field(
        label = label,
        value = value,
        isMonospace = shouldUseMonospace(value),
    )

    private fun isIndex(segment: String): Boolean = segment.isNotEmpty() && segment.all(Char::isDigit)

    /** List items are numbered from 1 for reading; the key's own index is shown in the export. */
    private fun indexLabel(segment: String): String = "#" + (segment.toIntOrNull()?.plus(1) ?: segment)

    private fun compareSegments(a: String, b: String): Int {
        val aIndex = isIndex(a)
        val bIndex = isIndex(b)
        return when {
            aIndex && bIndex -> {
                val x = a.trimStart('0')
                val y = b.trimStart('0')
                if (x.length != y.length) x.length - y.length else x.compareTo(y)
            }
            aIndex -> -1
            bIndex -> 1
            else -> a.compareTo(b)
        }
    }

    private const val VALUE_LABEL = "Value"
}
