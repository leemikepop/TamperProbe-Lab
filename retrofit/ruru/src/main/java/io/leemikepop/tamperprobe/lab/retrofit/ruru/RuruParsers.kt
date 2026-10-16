package io.leemikepop.tamperprobe.lab.retrofit.ruru

/** Pure parsing for the shadow probes, kept apart from Android calls so it is JVM-testable. */
internal object RuruParsers {
    /** `pm list packages` lines, read as PMCommand reads them. */
    fun parsePmList(lines: List<String>): Set<String> = lines.mapNotNull { raw ->
        val line = raw.trim()
        if (line.length > PREFIX.length && line.substring(0, PREFIX.length).equals(PREFIX, ignoreCase = true)) {
            line.substring(PREFIX.length).trim().ifEmpty { null }
        } else {
            null
        }
    }.toSet()

    private const val PREFIX = "package:"
}
