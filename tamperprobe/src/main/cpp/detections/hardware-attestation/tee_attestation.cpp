#include <sys/system_properties.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <ctime>
#include <set>
#include <string>
#include <vector>

#include "../../common/log.h"
#include "../../common/utils.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"
#include "tee_assessment.h"
#include "tee_common.h"
#include "tee_cert_parser.h"

namespace tamperprobe {
namespace {

constexpr const char* kTag = "TEE_ATTESTATION";

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char current) { return std::tolower(current); });
    return value;
}

std::string securityLevelToString(int level) {
    switch (level) {
        case 0: return "Software";
        case 1: return "TrustedEnvironment";
        case 2: return "StrongBox";
        default: return "Unknown";
    }
}

std::string verifiedBootStateToString(int state) {
    switch (state) {
        case 0: return "Verified";
        case 1: return "SelfSigned";
        case 2: return "Unverified";
        case 3: return "Failed";
        default: return "Unknown";
    }
}

std::vector<uint8_t> decodeHex(const std::string& value) {
    if (value.empty() || value.size() % 2 != 0) return {};
    auto digit = [](char current) -> int {
        if (current >= '0' && current <= '9') return current - '0';
        if (current >= 'a' && current <= 'f') return current - 'a' + 10;
        if (current >= 'A' && current <= 'F') return current - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> decoded(value.size() / 2);
    for (size_t index = 0; index < decoded.size(); ++index) {
        const int high = digit(value[index * 2]);
        const int low = digit(value[index * 2 + 1]);
        if (high < 0 || low < 0) return {};
        decoded[index] = static_cast<uint8_t>((high << 4) | low);
    }
    return decoded;
}

std::string systemProperty(const char* name) {
    std::vector<char> value(PROP_VALUE_MAX, '\0');
    const int length = __system_property_get(name, value.data());
    // The returned length is the stored length, which can include a NUL inside the value:
    // a Xiaomi 13T Pro stores ro.boot.vbmeta.digest as 64 hex digits plus a NUL. getprop and
    // the Java API stop at the NUL, so this does too; otherwise the digest comparison fails
    // on that one byte and reports a clean, locked phone as MODERATE.
    return length > 0 ? std::string(value.data(), strnlen(value.data(), value.size()))
                      : std::string();
}

std::string normalizeDigest(std::string value) {
    value = lowercase(value);
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char current) {
                    return std::isspace(current) || current == ':';
                }),
                value.end());
    if (value.rfind("0x", 0) == 0) value.erase(0, 2);
    return value;
}

bool allZeroHex(const std::string& value) {
    return !value.empty() &&
           std::all_of(value.begin(), value.end(),
                       [](char current) { return current == '0'; });
}

std::string loadStatusJson(const std::string& filesDir) {
    if (filesDir.empty()) return "";
    const auto installed = readFile((filesDir + "/attestation_status.json").c_str());
    if (installed.first) return installed.second;
    const auto compatibility = readFile((filesDir + "/status.json").c_str());
    return compatibility.first ? compatibility.second : "";
}

struct RevocationResult {
    bool snapshotLoaded = false;
    bool snapshotValid = false;
    bool blocked = false;
    bool revoked = false;
    bool suspended = false;
    int expiredEntryCount = 0;
    nlohmann::json hits = nlohmann::json::array();
};

std::string currentUtcDate() {
    const std::time_t now = std::time(nullptr);
    std::tm utc{};
    if (now == static_cast<std::time_t>(-1) ||
        gmtime_r(&now, &utc) == nullptr) {
        return "";
    }
    char date[11] = {};
    return std::strftime(date, sizeof(date), "%Y-%m-%d", &utc) > 0
            ? std::string(date)
            : std::string();
}

RevocationResult evaluateRevocation(const std::string& source,
                                    const nlohmann::json& collector) {
    RevocationResult result;
    result.snapshotLoaded = !source.empty();
    if (source.empty()) return result;
    const nlohmann::json document = nlohmann::json::parse(source, nullptr, false);
    if (document.is_discarded() || !document.is_object() ||
        !document.contains("entries") || !document["entries"].is_object()) {
        return result;
    }
    result.snapshotValid = true;
    const auto& entries = document["entries"];
    std::set<std::string> visited;
    const std::string today = currentUtcDate();

    auto inspect = [&](const char* sourceName, int index, const std::string& rawKey) {
        const std::string key = lowercase(rawKey);
        if (key.empty() || !visited.insert(key).second) return;
        const auto match = entries.find(key);
        if (match == entries.end() || !match->is_object()) return;
        const std::string expires =
                match->value("expires", std::string());
        if (!today.empty() && !expires.empty() && expires < today) {
            ++result.expiredEntryCount;
            return;
        }
        const std::string status =
                match->value("status", std::string("UNKNOWN"));
        const std::string reason =
                match->value("reason", std::string("UNKNOWN"));
        result.hits.push_back({{"source", sourceName},
                               {"index", index},
                               {"status", status},
                               {"reason", reason}});
        switch (tee_common::classifyRevocationStatus(status)) {
            case tee_common::RevocationStatus::REVOKED:
                result.revoked = true;
                break;
            case tee_common::RevocationStatus::SUSPENDED:
                result.suspended = true;
                break;
            case tee_common::RevocationStatus::NORMAL:
                break;
        }
    };

    constexpr const char* kSerialsKey = "chainSerialsHex";
    if (collector.contains(kSerialsKey) &&
        collector[kSerialsKey].is_array()) {
        int index = 0;
        for (const auto& serial : collector[kSerialsKey]) {
            if (serial.is_string()) {
                inspect(kSerialsKey, index, serial.get<std::string>());
            }
            ++index;
        }
    }
    result.blocked = result.revoked || result.suspended;
    return result;
}

}  // namespace

class TeeAttestationDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        nlohmann::json payload = {
                {"attestation",
                 {{"certificateAvailable", false},
                  {"certificateChainLength", 0},
                  {"chain",
                   {{"signaturesChecked", 0},
                    {"signaturesValid", false},
                    {"trustedRootState", "unavailable"},
                    {"trustedRootCount", 0},
                    {"attestationCertificateIndex", -1},
                    {"attestationExtensionCount", 0},
                    {"rkpProvisioningExtensionPresent", false},
                    {"rkpProvisioningCertificateIndex", -1},
                    {"provisioningExpiryState", "not_applicable"},
                    {"certificateValidity", nlohmann::json::array()}}},
                  {"challenge",
                   {{"expectedLength", 32},
                    {"present", false},
                    {"matches", false}}},
                  {"versions",
                   {{"attestationVersion", 0},
                    {"keymasterVersion", 0},
                    {"attestationSecurityLevel", "Unknown"},
                    {"attestationSecurityLevelCode", -1},
                    {"keymasterSecurityLevel", "Unknown"},
                    {"keymasterSecurityLevelCode", -1}}},
                  {"hasAttestationExtension", false},
                  {"rootOfTrust",
                   {{"parseOk", false},
                    {"deviceLocked", false},
                    {"verifiedBootState", "Unknown"},
                    {"verifiedBootStateCode", -1},
                    {"verifiedBootKeyHex", ""},
                    {"verifiedBootHashHex", ""}}},
                  {"bootConsistency",
                   {{"runtimeDigestAvailable", false},
                    {"runtimeDigestHex", ""},
                    {"attestedDigestHex", ""},
                    {"comparable", false},
                    {"matches", false},
                    {"zeroBootKey", false},
                    {"zeroBootHash", false}}},
                  {"revocation",
                   {{"statusJsonLoaded", false},
                    {"validationState", "unavailable"},
                    {"revoked", false},
                    {"suspended", false},
                    {"expiredEntryCount", 0},
                    {"hits", nlohmann::json::array()}}}}},
                {"findings", nlohmann::json::array()},
                {"collectionWarnings", nlohmann::json::array()}};

        tee_common::AttestationAssessmentInput assessmentInput;
        auto addFinding = [&](const char* id, const char* summary,
                              const std::string& detail,
                              EvidenceStrength strength) {
            payload["findings"].push_back({{"id", id},
                                           {"summary", summary},
                                           {"detail", detail},
                                           {"strength", evidenceStrengthName(strength)}});
            switch (strength) {
                case EvidenceStrength::STRONG:
                    ++assessmentInput.strongFindingCount;
                    break;
                case EvidenceStrength::MODERATE:
                    ++assessmentInput.moderateFindingCount;
                    break;
                case EvidenceStrength::WEAK:
                    ++assessmentInput.weakFindingCount;
                    break;
                default:
                    break;
            }
        };
        auto addWarning = [&](const char* source, const std::string& state,
                              const std::string& detail) {
            payload["collectionWarnings"].push_back(
                    {{"source", source}, {"state", state}, {"detail", detail}});
        };

        if (scanContext.env == nullptr || scanContext.androidContext == nullptr) {
            payload["collectionError"] = "JNI/Context not initialized";
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        const tee_common::CollectorResult collected =
                tee_common::collectAttestation(
                        scanContext.env, scanContext.androidContext, kTag);
        if (!collected.invoked) {
            payload["collectionError"] = collected.error;
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }
        const nlohmann::json collector =
                nlohmann::json::parse(collected.json, nullptr, false);
        if (collector.is_discarded() || !collector.is_object()) {
            payload["collectionError"] = "Keystore collector returned malformed JSON";
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }

        const std::string collectionState =
                collector.value("collectionState", std::string("collection_failed"));
        if (collectionState == "collection_failed") {
            payload["collectionError"] =
                    collector.value("errorCategory", std::string("collection_failed"));
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }
        if (collectionState != "ok") {
            addWarning("android_keystore", collectionState,
                       collector.value("errorCategory", std::string("provider_error")));
            return {DetectionAssessment::inconclusive(), payload.dump()};
        }
        if (!collector.value("aliasCleanupSucceeded", false)) {
            addWarning("keystore_alias", "cleanup_failed",
                       "The temporary attestation alias could not be confirmed absent.");
        }

        auto& attestation = payload["attestation"];
        const int chainLength =
                collector.value("certificateChainLength", 0);
        attestation["certificateAvailable"] = chainLength > 0;
        attestation["certificateChainLength"] = chainLength;
        attestation["chain"]["signaturesChecked"] =
                collector.value("chainSignaturesChecked", 0);
        attestation["chain"]["signaturesValid"] =
                collector.value("chainSignaturesValid", false);
        attestation["chain"]["trustedRootState"] =
                collector.value("trustedRootState", std::string("roots_unavailable"));
        attestation["chain"]["trustedRootCount"] =
                collector.value("trustedRootCount", 0);
        attestation["chain"]["attestationCertificateIndex"] =
                collector.value("attestationCertificateIndex", -1);
        attestation["chain"]["attestationExtensionCount"] =
                collector.value("attestationExtensionCount", 0);
        attestation["chain"]["rkpProvisioningExtensionPresent"] =
                collector.value("rkpProvisioningExtensionPresent", false);
        attestation["chain"]["rkpProvisioningCertificateIndex"] =
                collector.value("rkpProvisioningCertificateIndex", -1);
        attestation["chain"]["certificateValidity"] =
                collector.value("certificateValidity", nlohmann::json::array());
        const bool rkpProvisioningPresent =
                collector.value("rkpProvisioningExtensionPresent", false);
        const bool legacyFactoryRoot =
                collector.value("legacyFactoryRoot", false);
        bool certificateValidityComplete = true;
        std::string provisioningExpiryState =
                rkpProvisioningPresent ? "valid" : "not_applicable";
        const auto validity =
                collector.value("certificateValidity", nlohmann::json::array());
        if (!validity.is_array() ||
            static_cast<int>(validity.size()) != chainLength) {
            certificateValidityComplete = false;
            addWarning("certificate_validity", "incomplete",
                       "Validity state was not available for the complete chain.");
        } else {
            for (const auto& item : validity) {
                if (!item.is_object()) {
                    certificateValidityComplete = false;
                    continue;
                }
                const std::string state =
                        item.value("state", std::string("unknown"));
                if (state != "valid") {
                    if (rkpProvisioningPresent) {
                        provisioningExpiryState = state;
                        certificateValidityComplete = false;
                        addWarning(
                                "rkp_certificate_validity",
                                state,
                                "An RKP attestation-chain certificate is outside its validity interval.");
                    } else if (legacyFactoryRoot) {
                        addWarning(
                                "legacy_factory_certificate_validity",
                                state,
                                "An expired factory-provisioned certificate remains trustable under the documented legacy-root exception when it is not revoked.");
                    } else {
                        certificateValidityComplete = false;
                        addWarning(
                                "certificate_validity",
                                state,
                                "An attestation-chain certificate is outside its validity interval.");
                    }
                }
            }
        }
        attestation["chain"]["provisioningExpiryState"] =
                provisioningExpiryState;

        const int signaturesChecked =
                collector.value("chainSignaturesChecked", 0);
        const bool signaturesValid =
                collector.value("chainSignaturesValid", false);
        const bool signatureValidationComplete =
                chainLength > 1 && signaturesChecked == chainLength - 1;
        if (chainLength > 1 && !signaturesValid) {
            addFinding("chain_signature_invalid",
                       "Attestation certificate-chain signature validation failed",
                       "A certificate was not signed by the next certificate in the ordered chain.",
                       EvidenceStrength::STRONG);
        } else if (!signatureValidationComplete) {
            addWarning("certificate_chain", "incomplete",
                       "The full ordered certificate chain could not be validated.");
        }

        const std::string trustedRootState =
                collector.value("trustedRootState",
                                std::string("roots_unavailable"));
        if (trustedRootState != "trusted") {
            addWarning("attestation_root", trustedRootState,
                       trustedRootState == "unknown"
                               ? "The chain root is not in the bundled Google trust-anchor set."
                               : "The bundled attestation trust-anchor set was unavailable.");
        }
        if (collector.value("attestationExtensionCount", 0) > 1) {
            addWarning("attestation_extension", "multiple_occurrences",
                       "Only the first attestation extension in leaf-to-root order is interpreted.");
        }
        const bool attestationExtensionStructureComplete =
                collector.value("attestationExtensionCount", 0) == 1 &&
                collector.value("attestationCertificateIndex", -1) == 0;
        if (!attestationExtensionStructureComplete) {
            addWarning("attestation_extension", "unexpected_position",
                       "A single attestation extension was not present on the leaf certificate.");
        }

        const std::vector<uint8_t> certificate = decodeHex(
                collector.value("attestationCertificateHex", std::string()));
        const std::vector<uint8_t> expectedChallenge = decodeHex(
                collector.value("expectedChallengeHex", std::string()));
        tee_info_t info{};
        const bool parserOk = !certificate.empty() &&
                parse_tee_certificate(certificate.data(),
                                      static_cast<int>(certificate.size()),
                                      &info) == 0;
        if (!parserOk) {
            addWarning("attestation_parser", "unavailable",
                       "The selected attestation certificate could not be parsed.");
        } else {
            attestation["hasAttestationExtension"] =
                    has_tee_attestation_extension(&info) != 0;
            attestation["versions"]["attestationVersion"] =
                    info.attestation_version;
            attestation["versions"]["keymasterVersion"] =
                    info.keymaster_version;
            attestation["versions"]["attestationSecurityLevelCode"] =
                    info.security_level;
            attestation["versions"]["attestationSecurityLevel"] =
                    securityLevelToString(info.security_level);
            attestation["versions"]["keymasterSecurityLevelCode"] =
                    info.keymaster_security_level;
            attestation["versions"]["keymasterSecurityLevel"] =
                    securityLevelToString(info.keymaster_security_level);

            const bool challengePresent = info.attestation_challenge_len > 0;
            const bool challengeMatches =
                    challengePresent &&
                    expectedChallenge.size() ==
                            static_cast<size_t>(info.attestation_challenge_len) &&
                    std::equal(expectedChallenge.begin(), expectedChallenge.end(),
                               info.attestation_challenge);
            attestation["challenge"]["expectedLength"] =
                    expectedChallenge.size();
            attestation["challenge"]["present"] = challengePresent;
            attestation["challenge"]["matches"] = challengeMatches;
            if (challengePresent && !challengeMatches) {
                addFinding("challenge_mismatch",
                           "Attestation challenge does not match this scan",
                           "The attested challenge differs from the fresh per-scan challenge.",
                           EvidenceStrength::STRONG);
            } else if (!challengePresent) {
                addWarning("attestation_challenge", "missing",
                           "The attestation challenge could not be decoded.");
            }

            root_of_trust_t root{};
            if (get_tee_root_of_trust(&info, &root) == 0) {
                const std::string bootState =
                        verifiedBootStateToString(root.verified_boot_state);
                const std::string bootKey = root.verified_boot_key_hex;
                const std::string bootHash = root.verified_boot_hash_hex;
                attestation["rootOfTrust"]["parseOk"] = true;
                attestation["rootOfTrust"]["deviceLocked"] =
                        root.device_locked != 0;
                attestation["rootOfTrust"]["verifiedBootState"] = bootState;
                attestation["rootOfTrust"]["verifiedBootStateCode"] =
                        root.verified_boot_state;
                attestation["rootOfTrust"]["verifiedBootKeyHex"] = bootKey;
                attestation["rootOfTrust"]["verifiedBootHashHex"] = bootHash;

                if (root.device_locked == 0) {
                    addFinding("device_unlocked",
                               "Attested device lock state is false",
                               "RootOfTrust reported deviceLocked=false.",
                               EvidenceStrength::WEAK);
                }
                if (root.verified_boot_state != 0) {
                    addFinding("verified_boot_not_verified",
                               "Attested Verified Boot state is not Verified",
                               std::string("RootOfTrust reported ") + bootState + ".",
                               EvidenceStrength::WEAK);
                }

                const bool zeroRelevant =
                        root.verified_boot_state == 0 ||
                        root.verified_boot_state == 1;
                const bool zeroBootKey = zeroRelevant && allZeroHex(bootKey);
                const bool zeroBootHash = zeroRelevant && allZeroHex(bootHash);
                attestation["bootConsistency"]["zeroBootKey"] = zeroBootKey;
                attestation["bootConsistency"]["zeroBootHash"] = zeroBootHash;
                if (zeroBootKey) {
                    addFinding("zero_verified_boot_key",
                               "Verified Boot key is all zero",
                               "RootOfTrust contained an all-zero boot key in a comparable boot state.",
                               EvidenceStrength::MODERATE);
                }
                if (zeroBootHash) {
                    addFinding("zero_verified_boot_hash",
                               "Verified Boot hash is all zero",
                               "RootOfTrust contained an all-zero boot hash in a comparable boot state.",
                               EvidenceStrength::MODERATE);
                }

                const std::string runtimeDigest =
                        normalizeDigest(systemProperty("ro.boot.vbmeta.digest"));
                const std::string attestedDigest = normalizeDigest(bootHash);
                const bool runtimeAvailable = !runtimeDigest.empty();
                const bool comparable = zeroRelevant && runtimeAvailable &&
                                        !attestedDigest.empty();
                const bool matches = comparable &&
                                     runtimeDigest == attestedDigest;
                attestation["bootConsistency"]["runtimeDigestAvailable"] =
                        runtimeAvailable;
                // Both sides of the comparison, normalized as compared. Until 2026-09-18 only
                // the attested hash was published, so a mismatch -- one clean, locked Xiaomi
                // 13T Pro reported it -- could not be told apart from a wrong read on this
                // side: a truncated property, a different digest algorithm, or a spoofed one.
                attestation["bootConsistency"]["runtimeDigestHex"] = runtimeDigest;
                attestation["bootConsistency"]["attestedDigestHex"] = attestedDigest;
                attestation["bootConsistency"]["comparable"] = comparable;
                attestation["bootConsistency"]["matches"] = matches;
                if (comparable && !matches) {
                    addFinding("verified_boot_hash_mismatch",
                               "Attested and runtime Verified Boot digests disagree",
                               "RootOfTrust verifiedBootHash differs from ro.boot.vbmeta.digest.",
                               EvidenceStrength::MODERATE);
                }
            } else {
                addWarning("root_of_trust", "unavailable",
                           "RootOfTrust could not be decoded from the attestation record.");
            }

            if (!tee_common::isHardwareBackedAttestation(info.security_level)) {
                addFinding("software_backed_attestation",
                           "Attestation is not TEE or StrongBox backed",
                           std::string("attestationSecurityLevel=") +
                                   securityLevelToString(info.security_level) + ".",
                           EvidenceStrength::WEAK);
            }
        }

        // KeyMint crypto-primitive anomaly probes. These detect TrickyStore-style keybox
        // injection that leaves a valid attestation chain but breaks specific KeyMint
        // crypto operations.
        //
        // Only the single-use EC probe runs here now. The RSA-OAEP round trip moved to
        // TEE_KEYSTORE_CONSISTENCY on 2026-09-07 because an RSA-2048 generation cost
        // 335-903 ms on a Pixel 7 and 1,567 ms on a Redmi 13C - most of this detector.
        if (collector.contains("keyMintAnomalies") &&
                collector["keyMintAnomalies"].is_array()) {
            for (const auto& probe : collector["keyMintAnomalies"]) {
                if (!probe.is_object()) continue;
                const bool anomalous = probe.value("anomalous", false);
                if (!anomalous) continue;
                const std::string probeId = probe.value("id", std::string("unknown"));
                if (probeId == "single_use_ec") {
                    addFinding("single_use_ec_bypass",
                               "Single-use EC key usage-count enforcement bypassed",
                               "A key generated with setMaxUsageCount(1) permitted a second signing "
                               "operation. KeyMint usage-limit enforcement appears to be intercepted.",
                               EvidenceStrength::MODERATE);
                }
            }
        }

        const RevocationResult revocation =
                evaluateRevocation(loadStatusJson(scanContext.filesDir), collector);
        attestation["revocation"]["statusJsonLoaded"] =
                revocation.snapshotLoaded;
        attestation["revocation"]["validationState"] =
                revocation.snapshotValid ? "checked" : "unavailable";
        attestation["revocation"]["revoked"] = revocation.revoked;
        attestation["revocation"]["suspended"] = revocation.suspended;
        attestation["revocation"]["expiredEntryCount"] =
                revocation.expiredEntryCount;
        attestation["revocation"]["hits"] = revocation.hits;
        if (!revocation.snapshotValid) {
            addWarning("attestation_status", "unavailable",
                       "The offline revocation snapshot was missing or invalid.");
        }
        if (revocation.blocked) {
            addFinding("revoked_or_suspended_attestation_artifact",
                       "Attestation material matched the official status list",
                       revocation.revoked
                               ? "An attestation-chain certificate serial is REVOKED."
                               : "An attestation-chain certificate serial is SUSPENDED.",
                       EvidenceStrength::STRONG);
        }
        if (revocation.expiredEntryCount > 0) {
            addWarning("attestation_status", "expired_entry_ignored",
                       "A matched status entry had passed its optional expires date and was not treated as current revocation evidence.");
        }

        const bool challengeValidationComplete =
                parserOk && info.attestation_challenge_len > 0 &&
                !expectedChallenge.empty();
        assessmentInput.requiredValidationComplete =
                parserOk && challengeValidationComplete &&
                attestationExtensionStructureComplete &&
                signatureValidationComplete &&
                certificateValidityComplete &&
                trustedRootState == "trusted" &&
                revocation.snapshotValid;
        return {tee_common::assessAttestation(assessmentInput),
                payload.dump()};
    }

    const char* getId() const override { return "TEE_ATTESTATION"; }
};

REGISTER_DETECTION(TeeAttestationDetection);

}  // namespace tamperprobe
