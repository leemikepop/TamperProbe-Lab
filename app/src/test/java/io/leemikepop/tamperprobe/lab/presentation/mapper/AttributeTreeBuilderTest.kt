package io.leemikepop.tamperprobe.lab.presentation.mapper

import io.leemikepop.tamperprobe.lab.presentation.model.AttributeNodeUiModel
import io.leemikepop.tamperprobe.lab.presentation.model.AttributeNodeUiModel.Field
import io.leemikepop.tamperprobe.lab.presentation.model.AttributeNodeUiModel.Group
import io.leemikepop.tamperprobe.lab.presentation.model.AttributeNodeUiModel.GroupKind
import io.leemikepop.tamperprobe.lab.presentation.model.AttributeNodeUiModel.ValueList
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AttributeTreeBuilderTest {
    private val attributes = mapOf(
        "findings.0.check" to "custom_kernel_signature",
        "findings.0.detail" to "Known community kernel identifier matched: blu-spark",
        "findings.1.check" to "flash_locked",
        "findings.1.detail" to "",
        "bannerSources.0" to "uname",
        "bannerSources.1" to "proc_version",
        "comparedProperties.10" to "ro.k",
        "comparedProperties.2" to "ro.c",
        "attestation.bootStateCoherence.claim.flashLocked" to "true",
        "attestation.bootStateCoherence.claim.verifiedBootState" to "GREEN",
        "attestation.bootStateCoherence.observed.flashLocked" to "false",
        "hasCjk" to "false",
        "digest" to "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    )

    @Test
    fun everyValueIsKeptExactlyOnce() {
        val values = AttributeTreeBuilder.build(attributes).flatMap(::values)
        assertEquals(attributes.values.sorted(), values.sorted())
    }

    @Test
    fun plainFieldsComeFirstThenGroupedObjects() {
        val tree = AttributeTreeBuilder.build(attributes)

        val bannerSources = tree[0] as ValueList
        assertEquals("Banner Sources", bannerSources.label)
        assertEquals(listOf("uname", "proc_version"), bannerSources.values.map { it.value })

        val compared = tree[1] as ValueList
        assertEquals(listOf("#3", "#11"), compared.values.map { it.label })

        assertEquals(listOf("Digest", "Has Cjk"), tree.subList(2, 4).map { (it as Field).label })
        assertTrue((tree[2] as Field).isMonospace)
        assertFalse((tree[3] as Field).isMonospace)

        val attestation = tree[4] as Group
        assertEquals("Attestation › Boot State Coherence", attestation.title)
        assertEquals(GroupKind.SECTION, attestation.kind)
        assertEquals(listOf("Claim", "Observed"), attestation.children.map { (it as Group).title })

        val findings = tree[5] as Group
        assertEquals("Findings", findings.title)
        assertEquals(GroupKind.LIST, findings.kind)
        assertEquals(listOf("#1", "#2"), findings.children.map { (it as Group).title })
        val first = findings.children[0] as Group
        assertEquals(GroupKind.LIST_ITEM, first.kind)
        assertEquals(listOf("Check", "Detail"), first.children.map { (it as Field).label })
        assertFalse((first.children[1] as Field).isMonospace)
    }

    @Test
    fun keyThatIsAlsoAPrefixKeepsItsOwnValue() {
        val tree = AttributeTreeBuilder.build(mapOf("state" to "agree", "state.count" to "2"))
        assertEquals(listOf("agree", "2"), tree.flatMap(::values))
    }

    @Test
    fun topLevelIndexedAttributesBecomeOneItemPerIndex() {
        val tree = AttributeTreeBuilder.build(
            mapOf(
                "0.source" to "kallsyms",
                "0.errno" to "0",
                "1.source" to "modules",
                "1.errno" to "13",
            ),
        )
        assertEquals(listOf("#1", "#2"), tree.map { (it as Group).title })
        assertTrue(tree.all { (it as Group).kind == GroupKind.LIST_ITEM })
        assertEquals(listOf("0", "kallsyms", "13", "modules"), tree.flatMap(::values))
    }

    private fun values(node: AttributeNodeUiModel): List<String> = when (node) {
        is Field -> listOf(node.value)
        is ValueList -> node.values.map { it.value }
        is Group -> node.children.flatMap(::values)
    }
}
