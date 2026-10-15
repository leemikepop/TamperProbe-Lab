package io.leemikepop.tamperprobe.lab.lib

import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.os.Process
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.leemikepop.tamperprobe.lab.TamperProbe
import io.leemikepop.tamperprobe.lab.api.ScanRequest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeNoException
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.FileInputStream
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class PackageStorageVisibilityStatefulInstrumentedTest {
    @Test
    fun differentUidOwnerProducesDentryUnicodeAndErrnoMatrixWithoutResidue() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val nonce = UUID.randomUUID().toString().replace("-", "").take(16)
        val evidence = linkedMapOf<String, JsonElement>()

        val prepare = try {
            callOwner(context, "prepare", nonce)
        } catch (error: Exception) {
            assumeNoException(
                "Install :test-fixtures:storage-owner:debug before running this fixture",
                error,
            )
            return
        }
        assertTrue(prepare.getBoolean("ok"))
        assertNotEquals(Process.myUid(), prepare.getInt("ownerUid"))
        evidence["fixture"] = bundleEvidence(prepare)

        var cleanup = Bundle()
        try {
            shell("am force-stop $OWNER_PACKAGE")
            evidence["unheld"] = collectReadOnlyCorpus(currentUserId())

            shell(
                "am start -W -n " +
                    "$OWNER_PACKAGE/.StorageOwnerBootstrapActivity",
            )
            val held = callOwner(context, "hold", nonce)
            assertTrue(held.getBoolean("ok"))
            assertEquals(4, held.getInt("heldDirectoryCount"))
            evidence["holder"] = bundleEvidence(held)
            evidence["held"] = collectReadOnlyCorpus(currentUserId())
            evidence["errnoMatrix"] = collectErrnoMatrix(currentUserId(), nonce)
            evidence["runtimeDetector"] = collectRuntimeDetector(context)
        } finally {
            shell(
                "am start -W -n " +
                    "$OWNER_PACKAGE/.StorageOwnerBootstrapActivity",
            )
            cleanup = callOwner(context, "cleanup", nonce)
            evidence["cleanup"] = bundleEvidence(cleanup)
            val report = buildJsonObject {
                put("schemaVersion", 1)
                put("study", "package_storage_visibility")
                put("preliminary", true)
                put("serialRecorded", false)
                put("userId", currentUserId())
                evidence.forEach { (key, value) -> put(key, value) }
            }
            File(context.filesDir, RAW_FILE_NAME).writeText(report.toString())
        }

        assertTrue(cleanup.getBoolean("ok"))
        assertEquals("Fixture owner reported residual paths", 0, cleanup.getInt("residualCount"))
    }

    private fun collectReadOnlyCorpus(userId: Int): JsonArray = buildJsonArray {
        STORAGE_ROOTS.forEach { protectedRoot ->
            val base = "/storage/emulated/$userId"
            val canonical = "$base/Android/$protectedRoot/$OWNER_PACKAGE"
            add(probeRecord(protectedRoot, "canonical", "canonical", "", "", canonical))
            add(
                probeRecord(
                    protectedRoot,
                    "mixed_case",
                    "case_control",
                    "",
                    "mixed_case",
                    "$base/aNdRoId/${if (protectedRoot == "data") "DaTa" else "ObB"}/$OWNER_PACKAGE",
                ),
            )
            UNICODE_REPRESENTATIVES.forEach { representative ->
                val value = String(Character.toChars(representative.codePoint))
                val androidInside = "Android".let { it.substring(0, 3) + value + it.substring(3) }
                val rootInside = protectedRoot.let {
                    val split = it.length / 2
                    it.substring(0, split) + value + it.substring(split)
                }
                listOf(
                    "android_prefix" to "$base/${value}Android/$protectedRoot/$OWNER_PACKAGE",
                    "android_inside" to "$base/$androidInside/$protectedRoot/$OWNER_PACKAGE",
                    "${protectedRoot}_prefix" to
                        "$base/Android/$value$protectedRoot/$OWNER_PACKAGE",
                    "${protectedRoot}_inside" to
                        "$base/Android/$rootInside/$OWNER_PACKAGE",
                ).forEach { (placement, path) ->
                    add(
                        probeRecord(
                            protectedRoot = protectedRoot,
                            variantId = "${representative.id}_$placement",
                            variantType = "unicode",
                            codePoint = "U+${representative.codePoint.toString(16).uppercase()}",
                            placement = placement,
                            path = path,
                        ),
                    )
                }
            }
        }
    }

    private fun probeRecord(
        protectedRoot: String,
        variantId: String,
        variantType: String,
        codePoint: String,
        placement: String,
        path: String,
    ): JsonObject = buildJsonObject {
        put("protectedRoot", protectedRoot)
        put("variantId", variantId)
        put("variantType", variantType)
        put("codePoint", codePoint)
        put("placement", placement)
        put("probe", readOnlyProbe(path))
    }

    private fun readOnlyProbe(path: String): JsonObject = try {
        val status = Os.stat(path)
        buildJsonObject {
            put("state", "present")
            put("errno", 0)
            put("inode", status.st_ino)
            put("device", status.st_dev)
        }
    } catch (error: ErrnoException) {
        buildJsonObject {
            put(
                "state",
                when (error.errno) {
                    OsConstants.ENOENT, OsConstants.ENOTDIR -> "not_found"
                    OsConstants.EACCES, OsConstants.EPERM -> "denied"
                    else -> "error"
                },
            )
            put("errno", error.errno)
        }
    }

    private fun collectErrnoMatrix(userId: Int, nonce: String): JsonArray = buildJsonArray {
        STORAGE_ROOTS.forEach { protectedRoot ->
            val root = "/storage/emulated/$userId/Android/$protectedRoot/$OWNER_PACKAGE"
            operationRecord(protectedRoot, "mkdir", "$root/tamperprobe-$nonce-mkdir") {
                runNativeStorageOperation("mkdir", it, "")
            }.let(::add)
            operationRecord(protectedRoot, "create", "$root/tamperprobe-$nonce-create") {
                runNativeStorageOperation("create", it, "")
            }.let(::add)
            val renameSource = "$root/tamperprobe-$nonce-rename-source"
            val sourceBefore = readOnlyProbe(renameSource)
            operationRecord(protectedRoot, "rename", "$root/tamperprobe-$nonce-rename-target") {
                runNativeStorageOperation("rename", it, renameSource)
            }.let { record ->
                add(
                    JsonObject(
                        record +
                            ("sourceBefore" to sourceBefore) +
                            ("sourceAfter" to readOnlyProbe(renameSource)),
                    ),
                )
            }
            operationRecord(protectedRoot, "rmdir", "$root/tamperprobe-$nonce-rmdir") {
                runNativeStorageOperation("rmdir", it, "")
            }.let(::add)
            operationRecord(protectedRoot, "unlink", "$root/tamperprobe-$nonce-unlink") {
                runNativeStorageOperation("unlink", it, "")
            }.let(::add)
        }
    }

    private fun operationRecord(
        protectedRoot: String,
        operation: String,
        path: String,
        action: (String) -> Int,
    ): JsonObject {
        val before = readOnlyProbe(path)
        val errno = action(path)
        return buildJsonObject {
            put("protectedRoot", protectedRoot)
            put("operation", operation)
            put("pathToken", path.substringAfterLast('/'))
            put("errno", errno)
            put("before", before)
            put("after", readOnlyProbe(path))
        }
    }

    private fun callOwner(context: Context, method: String, nonce: String): Bundle =
        requireNotNull(context.contentResolver.call(OWNER_URI, method, nonce, null)) {
            "Storage-owner fixture returned no result for $method"
        }

    private fun bundleEvidence(bundle: Bundle): JsonObject = buildJsonObject {
        put("ok", bundle.getBoolean("ok"))
        put("ownerUid", bundle.getInt("ownerUid"))
        put("heldDirectoryCount", bundle.getInt("heldDirectoryCount"))
        put("residualCount", bundle.getInt("residualCount"))
        bundle.getString("error")?.let { put("error", it) }
    }

    private fun collectRuntimeDetector(context: Context): JsonObject {
        val result = TamperProbe.create(context)
            .scanBlocking(ScanRequest(setOf("PACKAGE_STORAGE_VISIBILITY")))
            .results
            .single()
        return buildJsonObject {
            put("id", result.descriptor.id)
            put("primaryEvidenceDomainId", result.descriptor.primaryEvidenceDomainId)
            put("outcome", result.outcome.name)
            put("strength", result.strength.name)
            put(
                "evidence",
                buildJsonArray {
                    result.unitResults.flatMap { it.records }.forEach { record ->
                        add(
                            buildJsonObject {
                                put("code", record.code)
                                put("summary", record.summary)
                                put(
                                    "attributes",
                                    JsonObject(
                                        record.attributes.mapValues { JsonPrimitive(it.value) },
                                    ),
                                )
                            },
                        )
                    }
                },
            )
            result.collectionError?.let { error ->
                put(
                    "collectionError",
                    buildJsonObject {
                        put("code", error.code)
                        put("message", error.message)
                    },
                )
            }
        }
    }

    private fun shell(command: String): String {
        val descriptor = InstrumentationRegistry.getInstrumentation()
            .uiAutomation
            .executeShellCommand(command)
        return FileInputStream(descriptor.fileDescriptor).bufferedReader().use { it.readText() }
            .also { descriptor.close() }
    }

    private fun currentUserId(): Int = Process.myUid() / 100000

    private external fun runNativeStorageOperation(
        operation: String,
        path: String,
        source: String,
    ): Int

    private data class UnicodeRepresentative(val codePoint: Int, val id: String)

    companion object {
        init {
            System.loadLibrary("tamperprobe_native")
        }

        const val RAW_FILE_NAME = "package-storage-visibility-stateful.json"
        private const val OWNER_PACKAGE =
            "io.leemikepop.tamperprobe.lab.fixture.storageowner"
        private val OWNER_URI =
            Uri.parse("content://io.leemikepop.tamperprobe.lab.fixture.storageowner.control")
        private val STORAGE_ROOTS = listOf("data", "obb")
        private val UNICODE_REPRESENTATIVES = listOf(
            UnicodeRepresentative(0x00AD, "soft_hyphen"),
            UnicodeRepresentative(0x034F, "combining_grapheme_joiner"),
            UnicodeRepresentative(0x061C, "arabic_letter_mark"),
            UnicodeRepresentative(0x115F, "hangul_filler"),
            UnicodeRepresentative(0x17B4, "khmer_inherent_vowel"),
            UnicodeRepresentative(0x180B, "mongolian_variation_selector"),
            UnicodeRepresentative(0x200B, "zero_width_space"),
            UnicodeRepresentative(0x202A, "bidi_embedding"),
            UnicodeRepresentative(0x2060, "word_joiner"),
            UnicodeRepresentative(0x3164, "hangul_filler_compat"),
            UnicodeRepresentative(0xFE00, "variation_selector"),
            UnicodeRepresentative(0xFEFF, "zero_width_no_break_space"),
            UnicodeRepresentative(0xFFA0, "halfwidth_hangul_filler"),
            UnicodeRepresentative(0x1BCA0, "shorthand_format"),
            UnicodeRepresentative(0x1D173, "musical_format"),
            UnicodeRepresentative(0xE0000, "tag_base"),
            UnicodeRepresentative(0xE0100, "variation_selector_supplement"),
        )
    }
}
