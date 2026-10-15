package io.leemikepop.tamperprobe.lab.internal.tee;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.KeyStoreException;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.function.Supplier;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Public-API-only Android Keystore collector shared by the SDK and standalone RASP.
 *
 * The class deliberately returns observations rather than a detector verdict. Native
 * TamperProbe code owns the final outcome and evidence-strength policy.
 */
public final class TeeKeystoreCollector {

    private static final String LOG_TAG = "TamperProbe";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final String RKP_PROVISIONING_OID = "1.3.6.1.4.1.11129.2.1.30";
    private static final String ROOT_ASSET = "tamperprobe/attestation_roots.json";
    private static final int ERROR_DEVICE_REQUIRES_UPGRADE_FOR_ATTESTATION = 17;
    private static final SecureRandom RANDOM = new SecureRandom();

    private TeeKeystoreCollector() {}

    public static String collectAttestation(Context context) {
        JSONObject result = new JSONObject();
        KeyStore keyStore = null;
        String alias = uniqueAlias("attestation");
        try {
            if (context == null) {
                result.put("collectionState", "collection_failed");
                result.put("errorCategory", "invalid_context");
                return result.toString();
            }

            byte[] challenge = new byte[32];
            RANDOM.nextBytes(challenge);
            result.put("challengeLength", challenge.length);
            result.put("expectedChallengeHex", toHex(challenge));

            keyStore = loadKeyStore();
            deleteAlias(keyStore, alias);
            long attestedKeyStartedAt = System.nanoTime();
            KeyPair pair = generateEcKeyPair(alias, challenge, false);
            logMicros("attested_ec_keygen", elapsedMicros(attestedKeyStartedAt));
            if (pair == null) {
                result.put("collectionState", "provider_error");
                result.put("errorCategory", "keypair_missing");
                return result.toString();
            }

            Certificate[] rawChain = keyStore.getCertificateChain(alias);
            if (rawChain == null || rawChain.length == 0) {
                result.put("collectionState", "provider_error");
                result.put("errorCategory", "certificate_chain_missing");
                return result.toString();
            }

            List<X509Certificate> chain = new ArrayList<>();
            for (Certificate certificate : rawChain) {
                if (!(certificate instanceof X509Certificate)) {
                    result.put("collectionState", "provider_error");
                    result.put("errorCategory", "non_x509_certificate");
                    return result.toString();
                }
                chain.add((X509Certificate) certificate);
            }

            JSONArray serialsHex = new JSONArray();
            JSONArray validity = new JSONArray();
            int attestationExtensionCount = 0;
            int attestationCertificateIndex = -1;
            int rkpProvisioningIndex = -1;
            Date now = new Date();

            for (int index = 0; index < chain.size(); index++) {
                X509Certificate certificate = chain.get(index);
                serialsHex.put(certificate.getSerialNumber().toString(16).toLowerCase());

                String validityState = "valid";
                try {
                    certificate.checkValidity(now);
                } catch (CertificateExpiredException error) {
                    validityState = "expired";
                } catch (CertificateNotYetValidException error) {
                    validityState = "not_yet_valid";
                }
                validity.put(new JSONObject()
                        .put("index", index)
                        .put("state", validityState));

                if (certificate.getExtensionValue(ATTESTATION_OID) != null) {
                    attestationExtensionCount++;
                    if (attestationCertificateIndex < 0) {
                        attestationCertificateIndex = index;
                    }
                }
                if (certificate.getExtensionValue(RKP_PROVISIONING_OID) != null) {
                    rkpProvisioningIndex = index;
                }
            }

            boolean chainSignaturesValid = true;
            int chainSignaturesChecked = 0;
            String chainSignatureError = "";
            for (int index = 0; index + 1 < chain.size(); index++) {
                try {
                    chain.get(index).verify(chain.get(index + 1).getPublicKey());
                    chainSignaturesChecked++;
                } catch (Exception error) {
                    chainSignaturesValid = false;
                    chainSignatureError = error.getClass().getSimpleName();
                    break;
                }
            }

            X509Certificate root = chain.get(chain.size() - 1);
            JSONObject trust = evaluateRootTrust(context, root);

            result.put("collectionState", "ok");
            result.put("certificateChainLength", chain.size());
            result.put("chainSerialsHex", serialsHex);
            result.put("certificateValidity", validity);
            result.put("chainSignaturesChecked", chainSignaturesChecked);
            result.put("chainSignaturesValid", chainSignaturesValid);
            result.put("chainSignatureError", chainSignatureError);
            result.put("trustedRootState", trust.getString("state"));
            result.put("trustedRootCount", trust.getInt("anchorCount"));
            result.put("legacyFactoryRoot", trust.optBoolean("legacyFactoryRoot", false));
            result.put("attestationExtensionCount", attestationExtensionCount);
            result.put("attestationCertificateIndex", attestationCertificateIndex);
            result.put("rkpProvisioningExtensionPresent", rkpProvisioningIndex >= 0);
            result.put("rkpProvisioningCertificateIndex", rkpProvisioningIndex);
            result.put(
                    "attestationCertificateHex",
                    attestationCertificateIndex >= 0
                            ? toHex(chain.get(attestationCertificateIndex).getEncoded())
                            : ""
            );

            // KeyMint anomaly probes — detect TrickyStore-style keybox injection signals
            result.put("keyMintAnomalies", runKeyMintAnomalyProbes());
        } catch (Throwable error) {
            recordError(result, classifyAttestationError(error), error);
        } finally {
            try {
                result.put("aliasCleanupSucceeded", deleteAliasQuietly(keyStore, alias));
            } catch (Exception ignored) {
                // Native validation treats an absent field as a cleanup warning.
            }
        }
        return result.toString();
    }

    /**
     * Runs a set of KeyMint crypto-primitive anomaly probes.
     *
     * TrickyStore injects a keybox into the TEE attestation chain but hooks keystore2 in a
     * way that leaves detectable inconsistencies in standard crypto operations:
     *
     * Single-use EC key: a key created with setMaxUsageCount(1) must raise
     * InvalidKeyException on the second signing attempt. If it succeeds instead, the
     * keystore2 usage-limit enforcement has been bypassed.
     *
     * The RSA-OAEP-SHA256 round-trip probe used to run here as well. It was measured on
     * 2026-09-07 at 335-903 ms on a Pixel 7 and 1,567 ms on a Redmi 13C - by itself the
     * majority of TEE_ATTESTATION. An
     * RSA-2048 generation is simply expensive, and an uncalibrated anomaly heuristic does
     * not justify that cost in the attestation detector, so it moved to
     * TEE_KEYSTORE_CONSISTENCY. See
     * runRsaOaepCheck below.
     *
     * Returns a JSONArray of probe result objects; anomalous=true signals are passed to
     * the native assessor to fire MODERATE evidence.
     */
    private static JSONArray runKeyMintAnomalyProbes() {
        JSONArray probes = new JSONArray();
        probes.put(timeProbe("single_use_ec", TeeKeystoreCollector::runSingleUseEcProbe));
        return probes;
    }

    /**
     * Runs one anomaly probe and stamps the result with its own elapsed time.
     *
     * <p>Each of these probes generates its own key in the Keystore, and one of them
     * generates an RSA-2048 key. A single figure for the whole detector hides which key
     * is expensive, which is exactly the question when the detector is 62% of a scan.
     */
    private static JSONObject timeProbe(String label, Supplier<JSONObject> probe) {
        long startedAt = System.nanoTime();
        JSONObject result = probe.get();
        logMicros(label, elapsedMicros(startedAt));
        return result;
    }

    private static long elapsedMicros(long startedAtNanos) {
        return (System.nanoTime() - startedAtNanos) / 1000L;
    }

    /**
     * Reports one Keystore operation's cost.
     *
     * <p>Deliberately a log line rather than a payload field: this is diagnostic telemetry
     * for performance work, and the detector payload is an evidence contract that should
     * not grow fields which say nothing about the device's integrity.
     */
    private static void logMicros(String label, long micros) {
        Log.i(LOG_TAG, "component=TeeKeystoreCollector event=keystore_op op=" + label
                + " durationMicros=" + micros);
    }

    private static JSONObject runSingleUseEcProbe() {
        String alias = uniqueAlias("single_use");
        KeyStore keyStore = null;
        JSONObject probe = new JSONObject();
        try {
            probe.put("id", "single_use_ec");
            keyStore = loadKeyStore();
            deleteAlias(keyStore, alias);

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
            )
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256);

            // setMaxUsageCount(1) requires API 31+
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                builder.setMaxUsageCount(1);
            } else {
                probe.put("state", "skipped");
                probe.put("reason", "api_level_below_31");
                probe.put("anomalous", false);
                return probe;
            }

            KeyPairGenerator generator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE);
            generator.initialize(builder.build());
            generator.generateKeyPair();

            byte[] message = new byte[32];
            RANDOM.nextBytes(message);

            // First use — must succeed
            boolean firstUseSucceeded = false;
            try {
                Signature signer = Signature.getInstance("SHA256withECDSA");
                signer.initSign((java.security.PrivateKey) keyStore.getKey(alias, null));
                signer.update(message);
                signer.sign();
                firstUseSucceeded = true;
            } catch (Throwable ignored) {
                // First use failing is itself anomalous but not the primary signal
            }

            // Second use — must fail (usage limit exhausted)
            boolean secondUseSucceeded = false;
            String secondUseError = "none";
            try {
                Signature signer2 = Signature.getInstance("SHA256withECDSA");
                signer2.initSign((java.security.PrivateKey) keyStore.getKey(alias, null));
                signer2.update(message);
                signer2.sign();
                secondUseSucceeded = true;
            } catch (InvalidKeyException ignored) {
                secondUseError = "InvalidKeyException";
            } catch (Throwable error) {
                secondUseError = error.getClass().getSimpleName();
            }

            // Anomalous = second use should NOT succeed; if it does, usage enforcement bypassed
            boolean anomalous = firstUseSucceeded && secondUseSucceeded;
            probe.put("state", "completed");
            probe.put("firstUseSucceeded", firstUseSucceeded);
            probe.put("secondUseSucceeded", secondUseSucceeded);
            probe.put("secondUseError", secondUseError);
            probe.put("anomalous", anomalous);
        } catch (Throwable error) {
            try {
                probe.put("state", "collection_failed");
                probe.put("errorClass", deepestCause(error).getClass().getSimpleName());
                probe.put("anomalous", false);
            } catch (Exception ignored) { /* */ }
        } finally {
            deleteAliasQuietly(keyStore, alias);
        }
        return probe;
    }

    /**
     * Adapts the RSA-OAEP round-trip probe to this detector's check vocabulary.
     *
     * <p>The probe itself is unchanged: an encrypt-then-decrypt round trip on a
     * hardware-backed RSA-2048 key must reproduce the plaintext, and a failure means the
     * KeyMint crypto implementation is not doing what it claims. Only where the result is
     * reported has changed. It is a required check, so a contradiction still carries the
     * same MODERATE weight it carried as an attestation finding.
     */
    private static void runRsaOaepCheck(JSONArray checks) {
        JSONObject probe = timeProbe("rsa_oaep_round_trip", TeeKeystoreCollector::runRsaOaepRoundTripProbe);
        String probeState = probe.optString("state", "collection_failed");
        String state;
        if (!"completed".equals(probeState)) {
            state = "unavailable";
        } else if (probe.optBoolean("anomalous", false)) {
            state = "contradiction";
        } else {
            state = "passed";
        }
        addCheck(checks, "rsa_oaep_sha256", true, state, probe);
    }

    private static JSONObject runRsaOaepRoundTripProbe() {
        String alias = uniqueAlias("rsa_oaep");
        KeyStore keyStore = null;
        JSONObject probe = new JSONObject();
        try {
            probe.put("id", "rsa_oaep_sha256");

            keyStore = loadKeyStore();
            deleteAlias(keyStore, alias);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE);
            kpg.initialize(new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
            )
                    .setKeySize(2048)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build());
            kpg.generateKeyPair();

            byte[] plaintext = new byte[32];
            RANDOM.nextBytes(plaintext);

            OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);

            // Encrypt with public key
            Certificate cert = keyStore.getCertificate(alias);
            Cipher encCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            encCipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey(), oaepSpec);
            byte[] ciphertext = encCipher.doFinal(plaintext);

            // Decrypt with private key (hardware-backed)
            java.security.PrivateKey privateKey =
                    (java.security.PrivateKey) keyStore.getKey(alias, null);
            Cipher decCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            decCipher.init(Cipher.DECRYPT_MODE, privateKey, oaepSpec);
            byte[] decrypted = decCipher.doFinal(ciphertext);

            boolean roundTripSuccess = Arrays.equals(plaintext, decrypted);
            // anomalous = round-trip FAILS (BadPadding or mismatch from hooked crypto stack)
            probe.put("state", "completed");
            probe.put("roundTripSuccess", roundTripSuccess);
            probe.put("anomalous", !roundTripSuccess);
        } catch (Throwable error) {
            // A BadPaddingException during decryption is itself the anomaly signal
            boolean anomalous = containsCause(error, javax.crypto.BadPaddingException.class)
                    || containsCause(error, javax.crypto.IllegalBlockSizeException.class);
            try {
                probe.put("state", anomalous ? "crypto_failure" : "collection_failed");
                probe.put("errorClass", deepestCause(error).getClass().getSimpleName());
                probe.put("anomalous", anomalous);
                probe.put("roundTripSuccess", false);
            } catch (Exception ignored) { /* */ }
        } finally {
            deleteAliasQuietly(keyStore, alias);
        }
        return probe;
    }

    public static String checkOversizedChallenge(Context context, int challengeSize) {
        JSONObject result = new JSONObject();
        KeyStore keyStore = null;
        String alias = uniqueAlias("oversized");
        String stage = "setup";
        try {
            result.put("challengeSize", challengeSize);
            if (context == null) {
                result.put("state", "collection_failed");
                result.put("errorCategory", "invalid_context");
                return result.toString();
            }

            keyStore = loadKeyStore();
            deleteAlias(keyStore, alias);
            byte[] challenge = new byte[challengeSize];
            RANDOM.nextBytes(challenge);
            stage = "generate";
            generateEcKeyPair(alias, challenge, false);
            result.put("state", "accepted");
            result.put("errorCategory", "none");
        } catch (Throwable error) {
            int errorCode = numericKeyStoreError(error);
            // The tamper signal for this probe is the device ACCEPTING a challenge above
            // the documented 128-byte limit, so any rejection at parameter validation is
            // the clean outcome. Android does not use one error code for it: a Pixel 7 on
            // Android 17 reports ERROR_INCORRECT_USAGE where other builds report
            // ERROR_ATTESTATION_CHALLENGE_TOO_LARGE. Both count as rejection.
            //
            // Infrastructure failures deliberately do not: an unavailable keystore, a
            // permission denial, missing attestation keys or an absent StrongBox never
            // exercised the limit at all, so they fall through to provider_error and the
            // detector reports INCONCLUSIVE rather than claiming the device is clean.
            boolean strongBoxUnavailable =
                    containsCause(error, android.security.keystore.StrongBoxUnavailableException.class);
            boolean rejectedByCode =
                    errorCode == KeyStoreException.ERROR_ATTESTATION_CHALLENGE_TOO_LARGE
                            || errorCode == KeyStoreException.ERROR_INCORRECT_USAGE;
            boolean expectedRejection =
                    !strongBoxUnavailable
                            && (rejectedByCode
                                    || (errorCode < 0
                                            && containsCause(error, InvalidAlgorithmParameterException.class)));
            String rejectionCategory;
            if (errorCode == KeyStoreException.ERROR_ATTESTATION_CHALLENGE_TOO_LARGE) {
                rejectionCategory = "challenge_too_large";
            } else if (errorCode == KeyStoreException.ERROR_INCORRECT_USAGE) {
                rejectionCategory = "incorrect_usage";
            } else {
                rejectionCategory = "invalid_parameters";
            }
            result = new JSONObject();
            try {
                result.put("challengeSize", challengeSize);
                result.put("stage", stage);
                result.put("state", expectedRejection ? "rejected" : "provider_error");
                result.put(
                        "errorCategory",
                        expectedRejection ? rejectionCategory : classifyProviderError(error)
                );
                result.put("numericErrorCode", errorCode);
                result.put("errorClass", deepestCause(error).getClass().getSimpleName());
            } catch (Exception ignored) {
                return "{\"state\":\"collection_failed\",\"errorCategory\":\"json_encoding_failed\"}";
            }
        } finally {
            try {
                result.put("aliasCleanupSucceeded", deleteAliasQuietly(keyStore, alias));
            } catch (Exception ignored) {
                // Native validation treats an absent field as a cleanup warning.
            }
        }
        return result.toString();
    }

    public static String collectKeystoreConsistency(Context context) {
        JSONObject result = new JSONObject();
        JSONArray checks = new JSONArray();
        JSONArray warnings = new JSONArray();
        try {
            if (context == null) {
                result.put("collectionState", "collection_failed");
                result.put("errorCategory", "invalid_context");
                return result.toString();
            }

            runSignatureCheck(checks);
            runLifecycleCheck(checks);
            runCertificateEntryCheck(checks);
            runAesRoundTrip(checks);
            runRsaOaepCheck(checks);
            runStrongBoxDiagnostic(context, checks);

            result.put("collectionState", "ok");
            result.put("checks", checks);
            result.put("collectionWarnings", warnings);
        } catch (Throwable error) {
            recordError(result, "collector_failure", error);
            try {
                result.put("checks", checks);
                result.put("collectionWarnings", warnings);
            } catch (Exception ignored) {
                return "{\"collectionState\":\"collection_failed\",\"errorCategory\":\"json_encoding_failed\"}";
            }
        }
        return result.toString();
    }

    private static void runSignatureCheck(JSONArray checks) {
        String alias = uniqueAlias("signature");
        KeyStore keyStore = null;
        try {
            keyStore = loadKeyStore();
            deleteAlias(keyStore, alias);
            KeyPair pair = generateEcKeyPair(alias, null, false);
            byte[] message = new byte[32];
            RANDOM.nextBytes(message);
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(pair.getPrivate());
            signer.update(message);
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            Certificate leaf = keyStore.getCertificate(alias);
            verifier.initVerify(leaf.getPublicKey());
            verifier.update(message);
            boolean verified = verifier.verify(signature);
            JSONObject detail = new JSONObject();
            detail.put("keySecurityLevel", keySecurityLevel(pair));
            addCheck(
                    checks,
                    "ec_signature_roundtrip",
                    true,
                    verified ? "passed" : "contradiction",
                    detail
            );
        } catch (Throwable error) {
            addUnavailableCheck(checks, "ec_signature_roundtrip", true, error);
        } finally {
            addCleanupCheck(checks, "ec_signature_roundtrip", keyStore, alias);
        }
    }

    private static void runLifecycleCheck(JSONArray checks) {
        String alias = uniqueAlias("lifecycle");
        KeyStore keyStore = null;
        try {
            keyStore = loadKeyStore();
            deleteAlias(keyStore, alias);
            generateEcKeyPair(alias, null, false);
            byte[] first = keyStore.getCertificate(alias).getPublicKey().getEncoded();
            keyStore.deleteEntry(alias);
            boolean absentAfterDelete = !keyStore.containsAlias(alias);
            generateEcKeyPair(alias, null, false);
            byte[] second = keyStore.getCertificate(alias).getPublicKey().getEncoded();
            boolean freshMaterial = !Arrays.equals(first, second);
            JSONObject detail = new JSONObject()
                    .put("absentAfterDelete", absentAfterDelete)
                    .put("freshPublicMaterial", freshMaterial);
            addCheck(
                    checks,
                    "key_lifecycle",
                    true,
                    absentAfterDelete && freshMaterial ? "passed" : "contradiction",
                    detail
            );
        } catch (Throwable error) {
            addUnavailableCheck(checks, "key_lifecycle", true, error);
        } finally {
            addCleanupCheck(checks, "key_lifecycle", keyStore, alias);
        }
    }

    private static void runCertificateEntryCheck(JSONArray checks) {
        String keyAlias = uniqueAlias("certificate_source");
        String certificateAlias = uniqueAlias("certificate_entry");
        KeyStore keyStore = null;
        try {
            keyStore = loadKeyStore();
            deleteAlias(keyStore, keyAlias);
            deleteAlias(keyStore, certificateAlias);
            generateEcKeyPair(keyAlias, null, false);
            Certificate certificate = keyStore.getCertificate(keyAlias);
            keyStore.setCertificateEntry(certificateAlias, certificate);
            boolean trustedEntry =
                    keyStore.entryInstanceOf(certificateAlias, KeyStore.TrustedCertificateEntry.class);
            boolean privateKeyAbsent = keyStore.getKey(certificateAlias, null) == null;
            JSONObject detail = new JSONObject()
                    .put("trustedCertificateEntry", trustedEntry)
                    .put("privateKeyAbsent", privateKeyAbsent);
            addCheck(
                    checks,
                    "certificate_only_entry",
                    true,
                    trustedEntry && privateKeyAbsent ? "passed" : "contradiction",
                    detail
            );
        } catch (Throwable error) {
            addUnavailableCheck(checks, "certificate_only_entry", true, error);
        } finally {
            addCleanupCheck(checks, "certificate_source", keyStore, keyAlias);
            addCleanupCheck(checks, "certificate_only_entry", keyStore, certificateAlias);
        }
    }

    private static void runAesRoundTrip(JSONArray checks) {
        String alias = uniqueAlias("aes");
        KeyStore keyStore = null;
        try {
            keyStore = loadKeyStore();
            deleteAlias(keyStore, alias);
            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            generator.init(new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
            )
                    .setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build());
            SecretKey key = generator.generateKey();
            byte[] plaintext = new byte[32];
            RANDOM.nextBytes(plaintext);
            Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
            encrypt.init(Cipher.ENCRYPT_MODE, key);
            byte[] ciphertext = encrypt.doFinal(plaintext);
            Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
            decrypt.init(
                    Cipher.DECRYPT_MODE,
                    key,
                    new GCMParameterSpec(128, encrypt.getIV())
            );
            boolean matches = Arrays.equals(plaintext, decrypt.doFinal(ciphertext));
            addCheck(
                    checks,
                    "aes_gcm_roundtrip",
                    false,
                    matches ? "passed" : "contradiction",
                    new JSONObject().put("keySecurityLevel", keySecurityLevel(key))
            );
        } catch (Throwable error) {
            addUnavailableCheck(checks, "aes_gcm_roundtrip", false, error);
        } finally {
            addCleanupCheck(checks, "aes_gcm_roundtrip", keyStore, alias);
        }
    }

    private static void runStrongBoxDiagnostic(Context context, JSONArray checks) {
        boolean declared = context.getPackageManager().hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE
        );
        String alias = uniqueAlias("strongbox");
        KeyStore keyStore = null;
        if (!declared) {
            addCheck(
                    checks,
                    "strongbox_capability",
                    false,
                    "not_declared",
                    new JSONObject()
            );
            return;
        }
        try {
            keyStore = loadKeyStore();
            deleteAlias(keyStore, alias);
            KeyPair pair = generateEcKeyPair(alias, null, true);
            addCheck(
                    checks,
                    "strongbox_capability",
                    false,
                    "passed",
                    new JSONObject().put("keySecurityLevel", keySecurityLevel(pair))
            );
        } catch (Throwable error) {
            addUnavailableCheck(checks, "strongbox_capability", false, error);
        } finally {
            addCleanupCheck(checks, "strongbox_capability", keyStore, alias);
        }
    }

    private static KeyPair generateEcKeyPair(
            String alias,
            byte[] challenge,
            boolean strongBox
    ) throws Exception {
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
        )
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256);
        if (challenge != null) {
            builder.setAttestationChallenge(challenge);
        }
        if (strongBox) {
            builder.setIsStrongBoxBacked(true);
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEY_STORE
        );
        generator.initialize(builder.build());
        return generator.generateKeyPair();
    }

    private static String keySecurityLevel(KeyPair pair) {
        if (pair == null || pair.getPrivate() == null) return "unknown";
        try {
            KeyFactory factory = KeyFactory.getInstance(pair.getPrivate().getAlgorithm(), ANDROID_KEY_STORE);
            KeyInfo info = factory.getKeySpec(pair.getPrivate(), KeyInfo.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                return "level_" + info.getSecurityLevel();
            }
            return info.isInsideSecureHardware() ? "secure_hardware" : "software";
        } catch (Exception error) {
            return "unavailable";
        }
    }

    private static String keySecurityLevel(SecretKey key) {
        if (key == null) return "unknown";
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(
                    key.getAlgorithm(),
                    ANDROID_KEY_STORE
            );
            KeyInfo info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                return "level_" + info.getSecurityLevel();
            }
            return info.isInsideSecureHardware() ? "secure_hardware" : "software";
        } catch (Exception error) {
            return "unavailable";
        }
    }

    private static JSONObject evaluateRootTrust(Context context, X509Certificate root) {
        JSONObject result = new JSONObject();
        int count = 0;
        try (InputStream input = context.getAssets().open(ROOT_ASSET)) {
            String source = readUtf8(input);
            JSONObject rootDocument = new JSONObject(source);
            if (rootDocument.getInt("schemaVersion") != 1) {
                result.put("state", "roots_unavailable");
                result.put("anchorCount", 0);
                return result;
            }
            JSONArray anchors = rootDocument.getJSONArray("certificates");
            int legacyFactoryRootIndex = rootDocument.optInt("legacyFactoryRootIndex", -1);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            byte[] rootSpki = root.getPublicKey().getEncoded();
            int matchedAnchorIndex = -1;
            for (int index = 0; index < anchors.length(); index++) {
                String pem = anchors.getString(index);
                X509Certificate anchor = (X509Certificate) factory.generateCertificate(
                        new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII))
                );
                count++;
                if (Arrays.equals(rootSpki, anchor.getPublicKey().getEncoded())) {
                    matchedAnchorIndex = index;
                }
            }
            result.put("state", matchedAnchorIndex >= 0 ? "trusted" : "unknown");
            result.put("anchorCount", count);
            result.put(
                    "legacyFactoryRoot",
                    matchedAnchorIndex >= 0 && matchedAnchorIndex == legacyFactoryRootIndex
            );
        } catch (Throwable error) {
            try {
                result.put("state", "roots_unavailable");
                result.put("anchorCount", count);
            } catch (Exception ignored) {
                return new JSONObject();
            }
        }
        return result;
    }

    private static KeyStore loadKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
        return keyStore;
    }

    private static void deleteAlias(KeyStore keyStore, String alias) throws Exception {
        if (keyStore != null && keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias);
        }
    }

    private static boolean deleteAliasQuietly(KeyStore keyStore, String alias) {
        try {
            deleteAlias(keyStore, alias);
            return keyStore == null || !keyStore.containsAlias(alias);
        } catch (Exception ignored) {
            return false;
        }
    }

    private static void addCleanupCheck(
            JSONArray checks,
            String source,
            KeyStore keyStore,
            String alias
    ) {
        if (!deleteAliasQuietly(keyStore, alias)) {
            addCheck(
                    checks,
                    source + "_cleanup",
                    false,
                    "unavailable",
                    new JSONObject()
            );
        }
    }

    private static String uniqueAlias(String role) {
        byte[] suffix = new byte[12];
        RANDOM.nextBytes(suffix);
        return "tamperprobe_" + role + "_" + toHex(suffix);
    }

    private static void addCheck(
            JSONArray checks,
            String id,
            boolean required,
            String state,
            JSONObject detail
    ) {
        try {
            checks.put(new JSONObject()
                    .put("id", id)
                    .put("required", required)
                    .put("state", state)
                    .put("detail", detail));
        } catch (Exception ignored) {
            // The caller will expose an incomplete check set as inconclusive.
        }
    }

    private static void addUnavailableCheck(
            JSONArray checks,
            String id,
            boolean required,
            Throwable error
    ) {
        JSONObject detail = new JSONObject();
        try {
            detail.put("errorCategory", classifyProviderError(error));
            detail.put("numericErrorCode", numericKeyStoreError(error));
            detail.put("errorClass", deepestCause(error).getClass().getSimpleName());
        } catch (Exception ignored) {
            // Keep the unavailable state even when optional details cannot be encoded.
        }
        addCheck(checks, id, required, "unavailable", detail);
    }

    private static void recordError(JSONObject result, String category, Throwable error) {
        try {
            result.put(
                    "collectionState",
                    "invalid_context".equals(category) ? "collection_failed" : "provider_error"
            );
            result.put("errorCategory", category);
            result.put("numericErrorCode", numericKeyStoreError(error));
            result.put("errorClass", deepestCause(error).getClass().getSimpleName());
        } catch (Exception ignored) {
            // Returning an empty JSON object makes the native boundary fail closed.
        }
    }

    private static String classifyAttestationError(Throwable error) {
        int code = numericKeyStoreError(error);
        if (code == KeyStoreException.ERROR_ATTESTATION_KEYS_UNAVAILABLE) {
            return "attestation_keys_unavailable";
        }
        if (code == ERROR_DEVICE_REQUIRES_UPGRADE_FOR_ATTESTATION) {
            return "device_upgrade_required";
        }
        if (containsCause(error, InvalidAlgorithmParameterException.class)) {
            return "attestation_unsupported";
        }
        return classifyProviderError(error);
    }

    private static String classifyProviderError(Throwable error) {
        if (containsCause(error, android.security.keystore.StrongBoxUnavailableException.class)) {
            return "strongbox_unavailable";
        }
        if (containsCause(error, ProviderException.class)) {
            return "provider_error";
        }
        if (containsCause(error, InvalidAlgorithmParameterException.class)) {
            return "invalid_parameters";
        }
        return "operation_failed";
    }

    private static int numericKeyStoreError(Throwable error) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return -1;
        Throwable cursor = error;
        while (cursor != null) {
            if (cursor instanceof KeyStoreException) {
                return ((KeyStoreException) cursor).getNumericErrorCode();
            }
            cursor = cursor.getCause();
        }
        return -1;
    }

    private static boolean containsCause(
            Throwable error,
            Class<? extends Throwable> type
    ) {
        Throwable cursor = error;
        while (cursor != null) {
            if (type.isInstance(cursor)) return true;
            cursor = cursor.getCause();
        }
        return false;
    }

    private static Throwable deepestCause(Throwable error) {
        Throwable cursor = error;
        while (cursor.getCause() != null && cursor.getCause() != cursor) {
            cursor = cursor.getCause();
        }
        return cursor;
    }

    private static String toHex(byte[] value) {
        char[] alphabet = "0123456789abcdef".toCharArray();
        char[] output = new char[value.length * 2];
        for (int index = 0; index < value.length; index++) {
            int current = value[index] & 0xff;
            output[index * 2] = alphabet[current >>> 4];
            output[index * 2 + 1] = alphabet[current & 0x0f];
        }
        return new String(output);
    }

    private static String readUtf8(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = input.read(buffer)) >= 0) {
            output.write(buffer, 0, read);
        }
        return output.toString(StandardCharsets.UTF_8.name());
    }
}
