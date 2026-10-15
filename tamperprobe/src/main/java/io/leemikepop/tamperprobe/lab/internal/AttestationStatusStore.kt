package io.leemikepop.tamperprobe.lab.internal

import android.content.Context
import android.system.Os
import io.leemikepop.tamperprobe.lab.api.TamperProbeException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.io.FileOutputStream
import java.time.LocalDate

internal class AttestationStatusStore(
    private val context: Context,
) {
    private val targetFile = File(context.filesDir, FILE_NAME)

    fun ensureBundledSnapshot() {
        synchronized(lock) {
            if (targetFile.isFile && targetFile.length() > 0L) return
            val bytes = try {
                context.assets.open(ASSET_PATH).use { it.readBytes() }
            } catch (error: Exception) {
                throw TamperProbeException(
                    "ATTESTATION_SNAPSHOT_MISSING",
                    "Bundled attestation status snapshot is unavailable",
                    error,
                )
            }
            installLocked(bytes)
        }
    }

    fun install(bytes: ByteArray) {
        synchronized(lock) {
            installLocked(bytes)
        }
    }

    private fun installLocked(bytes: ByteArray) {
        AttestationStatusValidator.validate(bytes)

        val temporaryFile = File(context.filesDir, "$FILE_NAME.tmp")
        try {
            FileOutputStream(temporaryFile).use { output ->
                output.write(bytes)
                output.fd.sync()
            }
            Os.rename(temporaryFile.absolutePath, targetFile.absolutePath)
        } catch (error: Exception) {
            temporaryFile.delete()
            throw TamperProbeException(
                "ATTESTATION_STATUS_WRITE_FAILED",
                "Unable to install attestation status data",
                error,
            )
        }
    }

    private companion object {
        const val FILE_NAME = "attestation_status.json"
        const val ASSET_PATH = "tamperprobe/attestation_status.json"
        val lock = Any()
    }
}

internal object AttestationStatusValidator {
    fun validate(bytes: ByteArray) {
        if (bytes.isEmpty()) {
            throw TamperProbeException("INVALID_ATTESTATION_STATUS", "Attestation status JSON is empty")
        }
        try {
            val root = Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
            if (root.keys != setOf("entries")) {
                throw IllegalArgumentException("Unexpected top-level property")
            }
            val entries = root["entries"] as? JsonObject
                ?: throw IllegalArgumentException("Missing entries object")
            entries.forEach { (key, value) ->
                if (!KEY_PATTERN.matches(key)) {
                    throw IllegalArgumentException("Invalid attestation status key")
                }
                val item = value as? JsonObject
                    ?: throw IllegalArgumentException("Status entry must be an object")
                if (!ALLOWED_ENTRY_PROPERTIES.containsAll(item.keys)) {
                    throw IllegalArgumentException("Unexpected status entry property")
                }
                val status = item["status"]?.jsonPrimitive?.contentOrNull
                if (status !in ALLOWED_STATUSES) {
                    throw IllegalArgumentException("Status entry has an unsupported status")
                }
                item["reason"]?.jsonPrimitive?.contentOrNull?.let { reason ->
                    if (reason !in ALLOWED_REASONS) {
                        throw IllegalArgumentException("Status entry has an unsupported reason")
                    }
                }
                item["expires"]?.jsonPrimitive?.contentOrNull?.let(LocalDate::parse)
                item["comment"]?.jsonPrimitive?.contentOrNull?.let { comment ->
                    if (comment.length > 140) {
                        throw IllegalArgumentException("Status entry comment is too long")
                    }
                }
            }
        } catch (error: Exception) {
            throw TamperProbeException(
                "INVALID_ATTESTATION_STATUS",
                "Attestation status data must be a UTF-8 JSON object",
                error,
            )
        }
    }

    private val KEY_PATTERN = Regex("^[a-f1-9][a-f0-9]*$")
    private val ALLOWED_STATUSES = setOf("REVOKED", "SUSPENDED")
    private val ALLOWED_REASONS = setOf(
        "UNSPECIFIED",
        "KEY_COMPROMISE",
        "CA_COMPROMISE",
        "SUPERSEDED",
        "SOFTWARE_FLAW",
    )
    private val ALLOWED_ENTRY_PROPERTIES = setOf("status", "expires", "reason", "comment")
}
