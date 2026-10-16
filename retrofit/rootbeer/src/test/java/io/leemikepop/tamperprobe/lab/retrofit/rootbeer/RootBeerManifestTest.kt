package io.leemikepop.tamperprobe.lab.retrofit.rootbeer

import com.scottyab.rootbeer.UpstreamConstants
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The host's `<queries>` decide which of RootBeer's lookups can answer at all. They must name
 * exactly RootBeer's packages: a missing one would turn that package's lookup into a silent
 * negative, an extra one would widen visibility beyond what RootBeer's lists need.
 */
class RootBeerManifestTest {
    @Test
    fun manifestQueriesNameExactlyRootBeersPackages() {
        val document = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
            .newDocumentBuilder()
            .parse(File("src/main/AndroidManifest.xml"))
        val packages = document.getElementsByTagName("package").let { nodes ->
            (0 until nodes.length).map {
                nodes.item(it).attributes.getNamedItemNS(ANDROID_NAMESPACE, "name").nodeValue
            }
        }
        assertEquals(packages.size, packages.toSet().size)
        assertEquals(RootBeerRetrofit.declaredPackages(), packages.toSet())
        assertEquals(0, document.getElementsByTagName("uses-permission").length)
    }

    @Test
    fun theSpecsCoverEveryCheckOfIsRooted() {
        assertEquals(9, RootBeerSpecs.ALL.size)
        assertEquals(12, UpstreamConstants.rootManagementPackages.size)
        assertEquals(27, UpstreamConstants.dangerousPackages.size)
    }

    private companion object {
        const val ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
    }
}
