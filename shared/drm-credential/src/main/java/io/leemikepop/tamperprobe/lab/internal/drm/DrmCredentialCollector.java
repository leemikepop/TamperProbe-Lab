package io.leemikepop.tamperprobe.lab.internal.drm;

import android.content.Context;
import android.media.MediaDrm;
import android.media.NotProvisionedException;
import android.media.ResourceBusyException;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.UUID;

/**
 * Reads the device's Widevine credential state.
 *
 * <p>The credential matters because it is one of the few device facts a userspace
 * concealment module cannot restore. Widevine L1 provisioning is per-device key material
 * held by the DRM trustlet; unlocking the bootloader destroys it, and no module can
 * re-provision it. A module can rewrite {@code ro.boot.*} and a keybox spoofer can present
 * an attestation chain the device never earned, but neither produces a credential.
 *
 * <p>This class only reports what it observed. Whether the observation contradicts the
 * boot state the device claims is decided natively, alongside the property reads.
 *
 * <p>Deliberately absent: {@code deviceUniqueId} and {@code provisioningUniqueId}. Those
 * are device-unique identifiers and are never read, let alone emitted. {@code systemId}
 * identifies a provisioning batch rather than a handset and is the value the check turns
 * on, so it is reported.
 */
public final class DrmCredentialCollector {

    private static final UUID WIDEVINE_UUID =
            UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed");
    private static final String MIME_TYPE_MP4 = "video/mp4";
    private static final String PROPERTY_SECURITY_LEVEL = "securityLevel";
    private static final String PROPERTY_SYSTEM_ID = "systemId";
    private static final String PROPERTY_VERSION = "version";

    private DrmCredentialCollector() {
    }

    /**
     * @return a JSON object describing the Widevine credential, never null.
     */
    public static String collectDrmCredential(Context context) {
        JSONObject result = new JSONObject();
        JSONArray errors = new JSONArray();
        try {
            boolean supported = MediaDrm.isCryptoSchemeSupported(WIDEVINE_UUID);
            result.put("schemeSupported", supported);
            if (!supported) {
                result.put("errors", errors);
                return result.toString();
            }

            result.put(
                    "hardwareSecureAllSupported",
                    MediaDrm.isCryptoSchemeSupported(
                            WIDEVINE_UUID, MIME_TYPE_MP4, MediaDrm.SECURITY_LEVEL_HW_SECURE_ALL));

            MediaDrm drm = null;
            try {
                drm = new MediaDrm(WIDEVINE_UUID);
                readProperty(drm, PROPERTY_SECURITY_LEVEL, "securityLevel", result, errors);
                readProperty(drm, PROPERTY_SYSTEM_ID, "systemId", result, errors);
                readProperty(drm, PROPERTY_VERSION, "version", result, errors);
                probeSession(drm, result, errors);
            } finally {
                if (drm != null) {
                    releaseQuietly(drm);
                }
            }
        } catch (Throwable throwable) {
            // Any failure here is a collection issue, never evidence: an unavailable DRM
            // stack must not be read as a missing credential.
            appendError(errors, "collect", throwable);
        }

        try {
            result.put("errors", errors);
        } catch (JSONException ignored) {
            // A JSONObject.put of a JSONArray cannot fail; nothing useful to do anyway.
        }
        return result.toString();
    }

    private static void readProperty(
            MediaDrm drm, String property, String field, JSONObject result, JSONArray errors) {
        try {
            String value = drm.getPropertyString(property);
            JSONObject entry = new JSONObject();
            if (value == null) {
                entry.put("status", "unavailable");
            } else {
                entry.put("status", "available");
                entry.put("value", value);
            }
            result.put(field, entry);
        } catch (Throwable throwable) {
            appendError(errors, field, throwable);
            try {
                result.put(field, new JSONObject().put("status", "error"));
            } catch (JSONException ignored) {
                // Nothing further to record.
            }
        }
    }

    /**
     * Opens and immediately closes a session. The outcome separates a credential that is
     * merely absent from one that exists but only satisfies a lower security level.
     */
    private static void probeSession(MediaDrm drm, JSONObject result, JSONArray errors)
            throws JSONException {
        byte[] session = null;
        try {
            session = drm.openSession();
            result.put("sessionStatus", "success");
            try {
                result.put("sessionSecurityLevel", securityLevelName(drm.getSecurityLevel(session)));
            } catch (Throwable throwable) {
                appendError(errors, "sessionSecurityLevel", throwable);
            }
        } catch (NotProvisionedException exception) {
            result.put("sessionStatus", "not_provisioned");
        } catch (ResourceBusyException exception) {
            // Another application holds the DRM resource. Transient, and not evidence.
            result.put("sessionStatus", "resource_busy");
        } catch (Throwable throwable) {
            result.put("sessionStatus", "failure");
            appendError(errors, "openSession", throwable);
        } finally {
            if (session != null) {
                try {
                    drm.closeSession(session);
                } catch (Throwable ignored) {
                    // The session is released with the MediaDrm instance regardless.
                }
            }
        }
    }

    private static String securityLevelName(int level) {
        switch (level) {
            case MediaDrm.SECURITY_LEVEL_SW_SECURE_CRYPTO:
                return "sw_secure_crypto";
            case MediaDrm.SECURITY_LEVEL_SW_SECURE_DECODE:
                return "sw_secure_decode";
            case MediaDrm.SECURITY_LEVEL_HW_SECURE_CRYPTO:
                return "hw_secure_crypto";
            case MediaDrm.SECURITY_LEVEL_HW_SECURE_DECODE:
                return "hw_secure_decode";
            case MediaDrm.SECURITY_LEVEL_HW_SECURE_ALL:
                return "hw_secure_all";
            case MediaDrm.SECURITY_LEVEL_UNKNOWN:
            default:
                return "unknown";
        }
    }

    private static void releaseQuietly(MediaDrm drm) {
        try {
            drm.close();
        } catch (Throwable ignored) {
            // Releasing is best-effort; a failure here says nothing about the credential.
        }
    }

    private static void appendError(JSONArray errors, String stage, Throwable throwable) {
        try {
            // Class name and stage only. Vendor error strings can carry device-specific
            // detail that has no place in an evidence payload.
            errors.put(
                    new JSONObject()
                            .put("stage", stage)
                            .put("type", throwable.getClass().getName()));
        } catch (JSONException ignored) {
            // Nothing further to record.
        }
    }
}
