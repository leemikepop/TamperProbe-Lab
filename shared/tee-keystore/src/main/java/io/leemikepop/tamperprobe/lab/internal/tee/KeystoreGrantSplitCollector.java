package io.leemikepop.tamperprobe.lab.internal.tee;

import android.content.Context;
import android.os.Build;
import android.os.Process;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyStoreManager;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

/**
 * Reads one Keystore key's certificate chain twice, through two different lookup paths,
 * and reports whether the two readings agree.
 *
 * <p>The check needs no reference data, which is what makes it useful against a keybox
 * spoofer: a stored certificate chain is the same bytes to every reader, so a difference
 * between two readings of the same key proves the chain is being synthesised per lookup
 * rather than returned from storage. A layer that hooks the ordinary alias path but not
 * the grant path, or that decides what to serve based on who is asking, produces exactly
 * that difference.
 *
 * <p>The second path is a grant issued by the application to its own uid. Granting to a
 * separate isolated process would be a stronger reader, but an isolated process is denied
 * the Keystore service on every device, so that variant can never return anything.
 *
 * <p>A grant read-back can also deny that the key exists at all, although the alias path
 * has just returned its chain and the grant for that alias was issued. That is reported as
 * its own state, {@code grant_key_missing}, and only after a control shows the grant channel
 * works for this uid: a key generated without an attestation challenge is granted and read
 * back the same way. If the control fails too, the channel is broken rather than
 * contradictory, and the check reports unavailable.
 *
 * <p>Only digests and lengths leave this class. Certificates are never emitted.
 */
public final class KeystoreGrantSplitCollector {

    private static final String LOG_TAG = "TamperProbe";

    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String ALIAS_PREFIX = "tamperprobe_grant_split_";
    private static final String CONTROL_ALIAS_PREFIX = "tamperprobe_grant_split_control_";
    /**
     * The message AndroidKeyStoreProvider uses when keystore2 resolves a descriptor to no key
     * (KEY_NOT_FOUND) or to a certificate-only entry. Every other getKeyEntry failure is
     * rethrown with the keystore2 error as its cause, so a cause-less exception carrying this
     * message means specifically "there is no key behind this descriptor".
     */
    private static final String NO_ASYMMETRIC_KEY_MESSAGE = "No asymmetric key found";
    private static final int CHALLENGE_BYTES = 32;

    private KeystoreGrantSplitCollector() {
    }

    /**
     * @return a JSON object describing the two readings and whether they agree.
     */
    public static String collectGrantSplit(Context context) {
        JSONObject result = new JSONObject();
        try {
            result.put("apiLevel", Build.VERSION.SDK_INT);
            // KeyStoreManager, and with it the only documented way to issue a grant, first
            // ships in API 36. Below that the check is unavailable, which is not the same
            // as clean and must not be reported as clean.
            if (Build.VERSION.SDK_INT < 36) {
                result.put("available", false);
                result.put(
                        "unavailableReason",
                        "KeyStoreManager grant API requires API 36; this device is API "
                                + Build.VERSION.SDK_INT);
                return result.toString();
            }
            return collectOnSupportedApi(context, result);
        } catch (Throwable throwable) {
            return failure(result, "collect", throwable);
        }
    }

    private static String collectOnSupportedApi(Context context, JSONObject result)
            throws Exception {
        KeyStoreManager manager =
                context.getApplicationContext().getSystemService(KeyStoreManager.class);
        if (manager == null) {
            result.put("available", false);
            result.put("unavailableReason", "KeyStoreManager system service is unavailable");
            return result.toString();
        }

        final String alias = ALIAS_PREFIX + System.nanoTime();
        final int selfUid = Process.myUid();
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null);

        boolean granted = false;
        try {
            generateKey(alias, true);

            Certificate[] ownerChain = keyStore.getCertificateChain(alias);
            if (ownerChain == null || ownerChain.length == 0) {
                result.put("available", false);
                result.put("unavailableReason", "owner certificate chain was empty");
                return result.toString();
            }
            result.put("ownerChain", describeChain(ownerChain));

            long grantId = manager.grantKeyAccess(alias, selfUid);
            granted = true;
            result.put("grantIssued", true);

            List<java.security.cert.X509Certificate> granteeChain;
            try {
                granteeChain = manager.getGrantedCertificateChainFromId(grantId);
            } catch (UnrecoverableKeyException denied) {
                if (!deniesKeyExists(denied)) {
                    throw denied;
                }
                return reportGrantKeyMissing(manager, keyStore, selfUid, result);
            }
            result.put("grantReadback", "ok");
            if (granteeChain == null || granteeChain.isEmpty()) {
                result.put("available", false);
                result.put("unavailableReason", "granted certificate chain was empty");
                return result.toString();
            }
            Certificate[] granteeArray =
                    granteeChain.toArray(new Certificate[0]);
            result.put("granteeChain", describeChain(granteeArray));

            result.put("available", true);
            compare(ownerChain, granteeArray, result);
            return result.toString();
        } finally {
            if (granted) {
                try {
                    manager.revokeKeyAccess(alias, selfUid);
                } catch (Throwable ignored) {
                    // The key is deleted below regardless, which revokes with it.
                }
            }
            try {
                keyStore.deleteEntry(alias);
            } catch (Throwable ignored) {
                // A leaked test alias is harmless; it carries no secret and is unique.
            }
        }
    }

    /**
     * The alias path returned a chain and the grant was issued, yet the grant read-back says
     * there is no key. Before calling that a contradiction, show that the grant channel
     * itself works for this uid, with a key that carries no attestation challenge. Measured
     * on a Pixel 7 under TrickyStore: the attested key's read-back is denied and the
     * control's succeeds, which is what an interception layer produces when it synthesises
     * attested chains without leaving a real key behind the grant path.
     */
    private static String reportGrantKeyMissing(
            KeyStoreManager manager, KeyStore keyStore, int selfUid, JSONObject result)
            throws JSONException {
        result.put("grantReadback", "key_missing");
        String control = runGrantControl(manager, keyStore, selfUid);
        result.put("controlReadback", control);
        if (!"ok".equals(control)) {
            result.put("available", false);
            result.put(
                    "unavailableReason",
                    "grant read-back denied the key and the non-attested control failed too ("
                            + control + ")");
            return result.toString();
        }
        result.put("available", true);
        result.put("split", true);
        result.put("splitKind", "grant_key_missing");
        result.put("mismatchIndex", -1);
        return result.toString();
    }

    /**
     * Grants and reads back a key generated without an attestation challenge.
     *
     * @return {@code ok}, or {@code failed} with the stage and exception class. Messages are
     *     excluded for the same reason as in {@link #failure}.
     */
    private static String runGrantControl(KeyStoreManager manager, KeyStore keyStore, int selfUid) {
        final String alias = CONTROL_ALIAS_PREFIX + System.nanoTime();
        String stage = "generate";
        boolean granted = false;
        try {
            generateKey(alias, false);
            stage = "grant";
            long grantId = manager.grantKeyAccess(alias, selfUid);
            granted = true;
            stage = "readback";
            List<java.security.cert.X509Certificate> chain =
                    manager.getGrantedCertificateChainFromId(grantId);
            if (chain == null || chain.isEmpty()) {
                return "failed stage=readback type=empty_chain";
            }
            return "ok";
        } catch (Throwable throwable) {
            Log.w(LOG_TAG, "component=KeystoreGrantSplitCollector event=control_failed stage="
                    + stage, throwable);
            return "failed stage=" + stage + " type=" + throwable.getClass().getName();
        } finally {
            if (granted) {
                try {
                    manager.revokeKeyAccess(alias, selfUid);
                } catch (Throwable ignored) {
                    // Deleting the key below revokes with it.
                }
            }
            try {
                keyStore.deleteEntry(alias);
            } catch (Throwable ignored) {
                // A leaked control alias is harmless; it carries no secret and is unique.
            }
        }
    }

    /**
     * True only for the provider's "no key behind this descriptor" outcome. A read-back that
     * failed for any other reason, including a keystore2 error, carries a cause and stays a
     * collection failure.
     */
    private static boolean deniesKeyExists(UnrecoverableKeyException exception) {
        String message = exception.getMessage();
        return exception.getCause() == null
                && message != null
                && message.startsWith(NO_ASYMMETRIC_KEY_MESSAGE);
    }

    private static void generateKey(String alias, boolean attested) throws Exception {
        KeyGenParameterSpec.Builder spec =
                new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256);
        if (attested) {
            byte[] challenge = new byte[CHALLENGE_BYTES];
            new java.security.SecureRandom().nextBytes(challenge);
            spec.setAttestationChallenge(challenge);
        }
        KeyPairGenerator generator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
        generator.initialize(spec.build());
        generator.generateKeyPair();
    }

    /**
     * Length and digest per certificate. The encoded certificate itself is never emitted:
     * an attestation chain carries device and application identity.
     */
    private static JSONArray describeChain(Certificate[] chain) throws Exception {
        JSONArray described = new JSONArray();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (Certificate certificate : chain) {
            byte[] encoded = certificate.getEncoded();
            described.put(
                    new JSONObject()
                            .put("length", encoded.length)
                            .put("sha256", hex(digest.digest(encoded))));
        }
        return described;
    }

    private static void compare(Certificate[] owner, Certificate[] grantee, JSONObject result)
            throws Exception {
        if (owner.length != grantee.length) {
            result.put("split", true);
            result.put("splitKind", "chain_length");
            result.put("mismatchIndex", -1);
            return;
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        for (int index = 0; index < owner.length; index++) {
            byte[] ownerEncoded = owner[index].getEncoded();
            byte[] granteeEncoded = grantee[index].getEncoded();
            if (!MessageDigest.isEqual(
                    digest.digest(ownerEncoded), digest.digest(granteeEncoded))) {
                result.put("split", true);
                result.put("splitKind", index == 0 ? "leaf_certificate" : "chain_certificate");
                result.put("mismatchIndex", index);
                return;
            }
        }
        result.put("split", false);
        result.put("splitKind", "none");
        result.put("mismatchIndex", -1);
    }

    private static String failure(JSONObject result, String stage, Throwable throwable) {
        try {
            result.put("available", false);
            // Stage, exception class, and the causal chain's classes. Exception *messages*
            // are deliberately excluded: Keystore messages can carry alias and device
            // detail that has no place in an evidence payload. The class chain and the
            // originating frame are enough to locate a failure and carry nothing sensitive.
            StringBuilder reason = new StringBuilder("stage=").append(stage)
                    .append(" type=").append(throwable.getClass().getName());
            Throwable cause = throwable.getCause();
            int depth = 0;
            while (cause != null && depth++ < 4) {
                reason.append(" causedBy=").append(cause.getClass().getName());
                cause = cause.getCause();
            }
            StackTraceElement[] frames = throwable.getStackTrace();
            if (frames.length > 0) {
                reason.append(" at=").append(frames[0].getClassName())
                        .append('.').append(frames[0].getMethodName());
            }
            result.put("unavailableReason", reason.toString());
            // The full trace goes to the log rather than the payload, so a failure can be
            // diagnosed without widening the evidence contract.
            Log.w(LOG_TAG, "component=KeystoreGrantSplitCollector event=collect_failed stage="
                    + stage, throwable);
        } catch (JSONException ignored) {
            // Nothing further to record.
        }
        return result.toString();
    }

    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(Character.forDigit((value >> 4) & 0xf, 16));
            builder.append(Character.forDigit(value & 0xf, 16));
        }
        return builder.toString();
    }
}
