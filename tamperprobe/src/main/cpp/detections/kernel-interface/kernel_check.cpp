#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <sys/utsname.h>

#include <set>

#include "../../common/io_utils.h"
#include "../../common/jni_call.hpp"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"
#include "kernel_identity_coherence.h"

namespace tamperprobe {

namespace {

bool scanCjkGlyphs(const std::string& text, std::string& matchSample) {
    size_t i = 0;
    while (i < text.size()) {
        unsigned char c0 = static_cast<unsigned char>(text[i]);
        if (c0 < 0x80) {
            i++;
        } else if ((c0 & 0xE0) == 0xC0 && i + 1 < text.size()) {
            i += 2;
        } else if ((c0 & 0xF0) == 0xE0 && i + 2 < text.size()) {
            unsigned char c1 = static_cast<unsigned char>(text[i + 1]);
            unsigned char c2 = static_cast<unsigned char>(text[i + 2]);
            uint32_t cp = ((c0 & 0x0F) << 12) | ((c1 & 0x3F) << 6) | (c2 & 0x3F);
            // CJK Unified Ideographs: 0x4E00..0x9FFF
            // CJK Extension A: 0x3400..0x4DBF
            // CJK Compatibility: 0xF900..0xFAFF
            if ((cp >= 0x4E00 && cp <= 0x9FFF) ||
                (cp >= 0x3400 && cp <= 0x4DBF) ||
                (cp >= 0xF900 && cp <= 0xFAFF)) {
                matchSample = text.substr(i, 3);
                return true;
            }
            i += 3;
        } else if ((c0 & 0xF8) == 0xF0 && i + 3 < text.size()) {
            unsigned char c1 = static_cast<unsigned char>(text[i + 1]);
            unsigned char c2 = static_cast<unsigned char>(text[i + 2]);
            unsigned char c3 = static_cast<unsigned char>(text[i + 3]);
            uint32_t cp = ((c0 & 0x07) << 18) | ((c1 & 0x3F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F);
            // CJK Extensions B..I: 0x20000..0x2FA1F
            if (cp >= 0x20000 && cp <= 0x2FA1F) {
                matchSample = text.substr(i, 4);
                return true;
            }
            i += 4;
        } else {
            i++;
        }
    }
    return false;
}

bool scanEmoji(const std::string& text, std::string& matchSample) {
    size_t i = 0;
    while (i < text.size()) {
        unsigned char c0 = static_cast<unsigned char>(text[i]);
        if (c0 < 0x80) {
            i++;
        } else if ((c0 & 0xE0) == 0xC0 && i + 1 < text.size()) {
            i += 2;
        } else if ((c0 & 0xF0) == 0xE0 && i + 2 < text.size()) {
            unsigned char c1 = static_cast<unsigned char>(text[i + 1]);
            unsigned char c2 = static_cast<unsigned char>(text[i + 2]);
            uint32_t cp = ((c0 & 0x0F) << 12) | ((c1 & 0x3F) << 6) | (c2 & 0x3F);
            // Dingbats & Misc Symbols: 0x2600..0x27BF
            if (cp >= 0x2600 && cp <= 0x27BF) {
                matchSample = text.substr(i, 3);
                return true;
            }
            i += 3;
        } else if ((c0 & 0xF8) == 0xF0 && i + 3 < text.size()) {
            unsigned char c1 = static_cast<unsigned char>(text[i + 1]);
            unsigned char c2 = static_cast<unsigned char>(text[i + 2]);
            unsigned char c3 = static_cast<unsigned char>(text[i + 3]);
            uint32_t cp = ((c0 & 0x07) << 18) | ((c1 & 0x3F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F);
            // Standard Emoji blocks: 0x1F300..0x1FAFF, 0x1F1E0..0x1F1FF
            if ((cp >= 0x1F300 && cp <= 0x1FAFF) || (cp >= 0x1F1E0 && cp <= 0x1F1FF)) {
                matchSample = text.substr(i, 4);
                return true;
            }
            i += 4;
        } else {
            i++;
        }
    }
    return false;
}

bool scanTelegram(const std::string& text, std::string& matchSample) {
    std::string lowered = lowercase_copy(text);
    if (lowered.find("t.me/") != std::string::npos) {
        matchSample = "t.me/";
        return true;
    }
    if (lowered.find("telegram.me/") != std::string::npos) {
        matchSample = "telegram.me/";
        return true;
    }
    if (lowered.find("tg://") != std::string::npos) {
        matchSample = "tg://";
        return true;
    }
    const char* patterns[] = {" tg ", " tg-", "@tg", " telegram "};
    for (const char* p : patterns) {
        if (lowered.find(p) != std::string::npos) {
            matchSample = p;
            return true;
        }
    }
    return false;
}

bool scanAtMentions(const std::string& text, std::string& matchSample) {
    size_t pos = 0;
    while ((pos = text.find('@', pos)) != std::string::npos) {
        if (pos > 0 && (std::isalnum(static_cast<unsigned char>(text[pos - 1])) || text[pos - 1] == '.' || text[pos - 1] == '-')) {
            pos++;
            continue;
        }
        size_t end = pos + 1;
        while (end < text.size() && (std::isalnum(static_cast<unsigned char>(text[end])) || text[end] == '_')) {
            end++;
        }
        size_t len = end - (pos + 1);
        if (len >= 3) {
            if (end < text.size() && text[end] == '.') {
                pos = end;
                continue;
            }
            matchSample = text.substr(pos, end - pos);
            return true;
        }
        pos = end;
    }
    return false;
}

bool scanCustomKeywords(const std::string& text, std::string& matchSample) {
    static const char* customKernelMarkers[] = {
        "arter97", "franco", "elementalx", "blu_spark", "blu-spark", "sultan",
        "caf-", "SilkSmoothKernel", "NetHunter", "dirty", "custom",
        "perf+", "overclock", "xiaoxiaow", "qdykernel", "shirkneko",
        "aptkernel", "sukisu", "KernelSU", "APatch", "numbers",
        "cctv", "mirinfork", "brokestar", "Glow-v", "coolzyd9107",
        "aptusitu", "OKI"
    };

    for (const char* marker : customKernelMarkers) {
        if (std::strcmp(marker, "OKI") == 0) {
            if (text.find("OKI") != std::string::npos) {
                matchSample = "OKI";
                return true;
            }
        } else {
            if (contains_ignore_case(text, marker)) {
                matchSample = marker;
                return true;
            }
        }
    }
    return false;
}

// Root-framework symbol tokens, copied from Duck-Detector's kernel_probe.cpp
// (nativeroot/probes). A root framework that ships kernel components leaves these symbol
// names in /proc/kallsyms and /proc/modules, and sometimes in the uname banner of a
// custom kernel. This is a legacy technique: kallsyms and modules are readable by an app
// only on older Android (both return EACCES on the API 33 and API 37 fleet devices), so
// the token scan has no positive control here and is kept for older stacks.
const char* const kKernelSymbolTokens[] = {"ksu_", "kernelsu", "apatch",
                                           "kpatch", "supercall", "magisk"};

std::vector<std::string> scanKernelSymbolTokens(const std::string& haystack) {
    std::vector<std::string> matched;
    if (haystack.empty()) return matched;
    for (const char* token : kKernelSymbolTokens) {
        if (contains_ignore_case(haystack, token)) matched.emplace_back(token);
    }
    return matched;
}

// The Zygote snapshot of the kernel release. libcore fills the "os.version" system property
// from uname().release while Zygote initialises, and every app process forked from Zygote
// inherits that value, so it records the release as it was before this app started. Read
// through the scan's JNIEnv; any JNI failure leaves the source unreadable, never a guess.
std::string readZygoteOsVersion(const DetectionContext& scanContext, std::string& error) {
    JNIEnv* env = scanContext.env;
    if (env == nullptr) {
        error = "JNI environment not available";
        return {};
    }
    try {
        jni::ScopedLocalRef<jstring> key(env, env->NewStringUTF("os.version"));
        jni::ThrowIfExceptionPending(env);
        if (key.get() == nullptr) {
            error = "Could not allocate the property name";
            return {};
        }
        jni::ScopedLocalRef<jstring> value(
            env, jni::CallStaticMethod<jstring>(env, "java/lang/System", "getProperty",
                                                "(Ljava/lang/String;)Ljava/lang/String;",
                                                key.get()));
        if (value.get() == nullptr) {
            error = "System.getProperty(\"os.version\") returned null";
            return {};
        }
        return jni::JStringToString(env, value.get());
    } catch (const jni::JNIException&) {
        error = "System.getProperty(\"os.version\") raised a Java exception";
        return {};
    }
}

constexpr char kIdentityCoherenceUnitId[] = "kernel-check.identity-coherence";

}  // namespace

/**
 * Kernel-level integrity checks:
 * 1. kptr_restrict check: parse first 20 lines of /proc/kallsyms (>50% non-zero -> SIGNAL)
 * 2. /proc/version and uname signature scan (CJK, emoji, t.me/, @ mentions, custom kernel tags -> MODERATE SIGNAL)
 * 3. Bootloader state and kernel parameters from /proc/cmdline
 * 4. Kernel identity coherence: the Zygote snapshot of the release (os.version) against the
 *    live uname() release and the procfs exports of the same string (disagreement -> MODERATE)
 *
 * References: Duck-Detector kernelcheck/native_bridge.cpp & KernelCheckRepository.kt; the
 * identity cross-check adapts the idea of Duck-Detector's KernelIdentityConsistencyUtils.kt
 * (Apache-2.0). No code was copied.
 */
class KernelCheckDetection : public Detection {
   public:
    DetectionResult execute(const DetectionContext& scanContext) override {
        nlohmann::json payload;
        payload["findings"] = nlohmann::json::array();
        int hitCount = 0;

        // 1. Check kernel version and uname for custom compilation markers and signatures
        struct utsname uts{};
        bool unameOk = (uname(&uts) == 0);
        std::string release = unameOk ? std::string(uts.release) : "";
        std::string version = unameOk ? std::string(uts.version) : "";
        payload["kernelRelease"] = release;
        payload["kernelVersion"] = version;

        std::string procVersion = read_text_file("/proc/version", 4096);
        payload["procVersion"] = procVersion;

        std::string combinedIdentity = procVersion;
        if (!release.empty()) combinedIdentity += "\n" + release;
        if (!version.empty()) combinedIdentity += "\n" + version;

        bool hasCjk = false;
        std::string cjkSample;
        if (scanCjkGlyphs(combinedIdentity, cjkSample)) {
            hasCjk = true;
            hitCount++;
            nlohmann::json f;
            f["check"] = "custom_kernel_signature";
            f["marker"] = "cjk_glyphs";
            f["value"] = cjkSample;
            f["detail"] = "Kernel identity contains CJK characters: " + cjkSample;
            payload["findings"].push_back(f);
        }
        payload["hasCjk"] = hasCjk;

        bool hasEmoji = false;
        std::string emojiSample;
        if (scanEmoji(combinedIdentity, emojiSample)) {
            hasEmoji = true;
            hitCount++;
            nlohmann::json f;
            f["check"] = "custom_kernel_signature";
            f["marker"] = "emoji";
            f["value"] = emojiSample;
            f["detail"] = "Kernel identity contains emoji sequences";
            payload["findings"].push_back(f);
        }
        payload["hasEmoji"] = hasEmoji;

        bool hasTelegram = false;
        std::string tgSample;
        if (scanTelegram(combinedIdentity, tgSample)) {
            hasTelegram = true;
            hitCount++;
            nlohmann::json f;
            f["check"] = "custom_kernel_signature";
            f["marker"] = "telegram_link";
            f["value"] = tgSample;
            f["detail"] = "Kernel identity references Telegram channel or link: " + tgSample;
            payload["findings"].push_back(f);
        }
        payload["hasTelegram"] = hasTelegram;

        bool hasAtMention = false;
        std::string mentionSample;
        if (scanAtMentions(combinedIdentity, mentionSample)) {
            hasAtMention = true;
            hitCount++;
            nlohmann::json f;
            f["check"] = "custom_kernel_signature";
            f["marker"] = "at_mention";
            f["value"] = mentionSample;
            f["detail"] = "Kernel identity contains maintainer @ mention: " + mentionSample;
            payload["findings"].push_back(f);
        }
        payload["hasAtMention"] = hasAtMention;

        std::string keywordSample;
        std::vector<std::string> matchedKeywords;
        if (scanCustomKeywords(combinedIdentity, keywordSample)) {
            matchedKeywords.push_back(keywordSample);
            hitCount++;
            nlohmann::json f;
            f["check"] = "custom_kernel_signature";
            f["marker"] = "custom_kernel_keyword";
            f["value"] = keywordSample;
            f["detail"] = "Known community kernel identifier matched: " + keywordSample;
            payload["findings"].push_back(f);
        }
        payload["customKeywords"] = matchedKeywords;

        // Rule 3: a negative that concealment can produce is not trusted. When /proc/version
        // is unreadable, the banner scan above saw only what the uname syscall returned, and a
        // kernel-side uname spoof (SUSFS spoof_uname hooks newuname) returns a stock string
        // with no marker in it. That not-found is published as a concealable negative instead
        // of standing as an answer.
        const bool bannerFromUnameOnly = unameOk && procVersion.empty();
        payload["bannerSources"] = nlohmann::json::array();
        if (unameOk) payload["bannerSources"].push_back("uname");
        if (!procVersion.empty()) payload["bannerSources"].push_back("proc_version");
        payload["bannerConcealableNegatives"] = nlohmann::json::array();
        if (bannerFromUnameOnly && !hasCjk && !hasEmoji && !hasTelegram && !hasAtMention &&
            matchedKeywords.empty()) {
            payload["bannerConcealableNegatives"].push_back(
                {{"check", "custom_kernel_signature"},
                 {"source", "uname"},
                 {"concealable", true},
                 {"reason", "No marker in the uname banner, and /proc/version was unreadable; "
                            "a uname spoof produces the same absence."}});
        }

        // 2. Check /proc/cmdline for bootloader state and root parameters
        std::string cmdline = read_text_file("/proc/cmdline", 4096);
        payload["procCmdline"] = cmdline;
        if (!cmdline.empty()) {
            if (cmdline.find("androidboot.verifiedbootstate=orange") != std::string::npos) {
                hitCount++;
                nlohmann::json f;
                f["check"] = "bootloader_state";
                f["marker"] = "verifiedbootstate";
                f["value"] = "orange (unlocked)";
                f["detail"] = "Bootloader state is unlocked (orange)";
                payload["findings"].push_back(f);
            }
            if (cmdline.find("androidboot.verifiedbootstate=yellow") != std::string::npos) {
                hitCount++;
                nlohmann::json f;
                f["check"] = "bootloader_state";
                f["marker"] = "verifiedbootstate";
                f["value"] = "yellow (self-signed)";
                f["detail"] = "Bootloader loaded self-signed boot image (yellow)";
                payload["findings"].push_back(f);
            }
            if (cmdline.find("androidboot.flash.locked=0") != std::string::npos) {
                hitCount++;
                nlohmann::json f;
                f["check"] = "flash_locked";
                f["marker"] = "flash.locked";
                f["value"] = "0 (unlocked)";
                f["detail"] = "Flash lock state is unlocked (0)";
                payload["findings"].push_back(f);
            }
            if (cmdline.find("androidboot.vbmeta.device_state=unlocked") != std::string::npos) {
                hitCount++;
                nlohmann::json f;
                f["check"] = "vbmeta_device_state";
                f["marker"] = "vbmeta.device_state";
                f["value"] = "unlocked";
                f["detail"] = "vbmeta device state is unlocked";
                payload["findings"].push_back(f);
            }
            if (contains_ignore_case(cmdline, "magisk") ||
                contains_ignore_case(cmdline, "ksu") ||
                contains_ignore_case(cmdline, "apatch")) {
                hitCount++;
                nlohmann::json f;
                f["check"] = "cmdline_root_marker";
                f["marker"] = "root_framework";
                f["value"] = "Root framework reference in cmdline";
                f["detail"] = "Root framework reference detected in /proc/cmdline";
                payload["findings"].push_back(f);
            }
        }

        // 3. Check kallsyms visibility: parse top 20 lines
        FILE* kallsyms = fopen("/proc/kallsyms", "r");
        bool kallsymsReadable = (kallsyms != nullptr);
        int nonZeroCount = 0;
        int lineCount = 0;

        if (kallsyms) {
            char line[256];
            while (lineCount < 20 && fgets(line, sizeof(line), kallsyms)) {
                lineCount++;
                bool nonZero = false;
                for (int i = 0; line[i] != '\0' && line[i] != ' ' && line[i] != '\t' && line[i] != '\n'; ++i) {
                    if (line[i] != '0') {
                        nonZero = true;
                        break;
                    }
                }
                if (nonZero) {
                    nonZeroCount++;
                }
            }
            fclose(kallsyms);
        }

        payload["kallsymsReadable"] = kallsymsReadable;
        payload["nonZeroAddresses"] = nonZeroCount;
        payload["totalLinesScanned"] = lineCount;

        bool kptrExposed = (lineCount > 0 && nonZeroCount > (lineCount / 2));
        payload["kptrExposed"] = kptrExposed;
        payload["kptrRestrictDisabled"] = kptrExposed;
        double nonZeroRatio = lineCount > 0 ? static_cast<double>(nonZeroCount) / lineCount : 0.0;
        payload["nonZeroPointerRatio"] = nonZeroRatio;

        if (kptrExposed) {
            hitCount++;
            nlohmann::json f;
            f["check"] = "kptr_restrict_disabled";
            f["marker"] = "kptr_restrict";
            f["value"] = "Non-zero kernel symbol addresses visible (" + std::to_string(nonZeroCount) + "/" + std::to_string(lineCount) + ")";
            f["detail"] = "Kernel symbol addresses are exposed in /proc/kallsyms (>50% non-zero)";
            payload["findings"].push_back(f);
        }

        // Symbol-name scan over kallsyms, modules and the kernel identity banner. Bounded
        // reads; on modern Android both procfs files are EACCES and contribute nothing.
        const std::string kallsymsSymbols = read_text_file("/proc/kallsyms", 131072);
        const std::string modulesText = read_text_file("/proc/modules", 32768);
        const bool modulesReadable = !modulesText.empty();
        payload["modulesReadable"] = modulesReadable;

        std::set<std::string> symbolMatchSet;
        const std::string* const sources[] = {&combinedIdentity, &kallsymsSymbols, &modulesText};
        for (const std::string* source : sources) {
            for (const std::string& token : scanKernelSymbolTokens(*source)) {
                symbolMatchSet.insert(token);
            }
        }
        std::vector<std::string> symbolMatches(symbolMatchSet.begin(), symbolMatchSet.end());
        payload["kernelSymbolMatches"] = symbolMatches;
        if (bannerFromUnameOnly && symbolMatches.empty() && !kallsymsReadable && !modulesReadable) {
            payload["bannerConcealableNegatives"].push_back(
                {{"check", "kernel_symbol_token"},
                 {"source", "uname"},
                 {"concealable", true},
                 {"reason", "The symbol-token scan saw only the uname banner; a uname spoof "
                            "produces the same absence."}});
        }
        for (const std::string& token : symbolMatches) {
            hitCount++;
            nlohmann::json f;
            f["check"] = "kernel_symbol_token";
            f["marker"] = "root_symbol";
            f["value"] = token;
            f["detail"] = "Root-framework symbol token present in kernel symbols or banner: " + token;
            payload["findings"].push_back(f);
        }

        // 4. Kernel identity coherence. The kernel copies one utsname release into every
        // source below, and it cannot change without a reboot, so on an unmodified device
        // they all agree. A spoof that rewrites one surface after Zygote started (SUSFS
        // patching newuname from a late boot stage) leaves the Zygote snapshot and the live
        // syscall disagreeing. The procfs exports are best effort: an app's SELinux domain
        // usually cannot read them.
        std::string zygoteError;
        const std::string zygoteOsVersion = readZygoteOsVersion(scanContext, zygoteError);
        const std::string sysctlOsRelease = read_text_file("/proc/sys/kernel/osrelease", 256);
        const std::string procVersionRelease = kernel_identity::parseProcVersionRelease(procVersion);
        const std::vector<kernel_identity::ReleaseSource> identitySources = {
            {"zygote_os_version", zygoteOsVersion},
            {"uname_release", release},
            {"proc_sys_kernel_osrelease", sysctlOsRelease},
            {"proc_version_release", procVersionRelease},
        };
        const kernel_identity::CoherenceResult coherence =
            kernel_identity::compareReleases(identitySources);

        nlohmann::json identity = {
            {"state", kernel_identity::coherenceStateName(coherence.state)},
            {"readableSourceCount", static_cast<int>(coherence.readableSourceIds.size())},
            {"distinctReleaseCount", static_cast<int>(coherence.distinctReleases.size())},
            {"sources", nlohmann::json::array()},
            {"unreadableSources", coherence.unreadableSourceIds},
        };
        for (const auto& source : identitySources) {
            const std::string value = trim_copy(source.value);
            identity["sources"].push_back(
                {{"source", source.id}, {"readable", !value.empty()}, {"value", value}});
        }
        payload["identityCoherence"] = identity;

        // Agreement is a negative that a spoof applied before Zygote initialises (the SUSFS
        // reference module calls set_uname from post-fs-data) also produces: every source
        // then carries the spoofed string. It is published as a concealable negative.
        payload["identityConcealableNegatives"] = nlohmann::json::array();
        if (coherence.state == kernel_identity::CoherenceState::AGREE) {
            payload["identityConcealableNegatives"].push_back(
                {{"check", "kernel_identity_coherence"},
                 {"comparedSources", coherence.readableSourceIds},
                 {"concealable", true},
                 {"reason", "Every readable release source agrees; a spoof applied before Zygote "
                            "initialised makes them agree as well."}});
        }

        if (coherence.state == kernel_identity::CoherenceState::DISAGREE) {
            // MODERATE, as for BUILD_PATCH_COHERENCE and DRM_CREDENTIAL_COHERENCE. The
            // contradiction is sound as an argument (the release cannot change while the
            // kernel runs), but the snapshot side is a Java value that an in-process hook on
            // System.getProperty can rewrite, and no clean device has been measured on this
            // build yet. Raise the grade only once a clean control exists.
            std::string values;
            for (const auto& source : identity["sources"]) {
                if (!source["readable"].get<bool>()) continue;
                if (!values.empty()) values += ", ";
                values += source["source"].get<std::string>() + "=" +
                          source["value"].get<std::string>();
            }
            nlohmann::json f;
            f["check"] = "kernel_identity_mismatch";
            f["unitId"] = kIdentityCoherenceUnitId;
            f["marker"] = "release_disagreement";
            f["value"] = values;
            f["detail"] = "Kernel release sources disagree (" + values +
                          "); the release cannot change while the kernel runs, so at least one "
                          "source was rewritten.";
            payload["findings"].push_back(f);
        }

        // Honest availability. Three of this detector's sub-checks read files that an app
        // cannot open on current Android: kallsyms (the kptr and symbol checks), modules
        // (the symbol check), and cmdline (the bootloader-state check). When they are
        // unavailable a not-found is not a clean answer, so each unreadable source is
        // recorded as a collection issue, which marks the unit PARTIAL. The uname banner
        // scan is always available; when it is the banner's only source its negative is
        // listed in bannerConcealableNegatives. The detector still reports NOT_OBSERVED
        // rather than INCONCLUSIVE, as the SELinux policy oracle does for a negative resting
        // on concealable absences, and leaves the distinction to the published records.
        payload["collectionErrors"] = nlohmann::json::array();
        if (!kallsymsReadable) {
            payload["collectionErrors"].push_back(
                {{"source", "kallsyms"}, {"errno", 0},
                 {"message", "/proc/kallsyms is not readable by this process; the kptr and "
                             "symbol checks could not run."}});
        }
        if (!modulesReadable) {
            payload["collectionErrors"].push_back(
                {{"source", "modules"}, {"errno", 0},
                 {"message", "/proc/modules is not readable by this process; the module "
                             "symbol check could not run."}});
        }
        if (cmdline.empty()) {
            payload["collectionErrors"].push_back(
                {{"source", "cmdline"}, {"errno", 0},
                 {"message", "/proc/cmdline is not readable by this process; the "
                             "bootloader-state check could not run."}});
        }
        // /proc/version and uname feed both units (the banner scan and the identity
        // comparison), so their entries are deliberately left for both; the other identity
        // sources feed only the coherence unit.
        if (procVersion.empty()) {
            payload["collectionErrors"].push_back(
                {{"source", "proc_version"}, {"errno", 0},
                 {"message", "/proc/version is not readable by this process; the banner scan "
                             "saw only uname and the identity comparison could not use it."}});
        }
        if (!unameOk) {
            payload["collectionErrors"].push_back(
                {{"source", "uname"}, {"errno", 0},
                 {"message", "uname() failed; neither the banner scan nor the identity "
                             "comparison could use it."}});
        }
        if (sysctlOsRelease.empty()) {
            payload["collectionErrors"].push_back(
                {{"source", "proc_sys_kernel_osrelease"}, {"errno", 0},
                 {"message", "/proc/sys/kernel/osrelease is not readable by this process."}});
        }
        if (trim_copy(zygoteOsVersion).empty()) {
            payload["collectionErrors"].push_back(
                {{"source", "zygote_os_version"}, {"errno", 0},
                 {"message", zygoteError.empty()
                                 ? std::string("System.getProperty(\"os.version\") is empty.")
                                 : zygoteError}});
        }
        if (coherence.state == kernel_identity::CoherenceState::UNAVAILABLE) {
            // Fewer than two readable sources compare nothing: the unit is unavailable, never
            // a negative. The values that were read stay on the entry so they are published.
            nlohmann::json entry = {
                {"source", "kernel_identity"},
                {"errno", 0},
                {"readableSourceCount", static_cast<int>(coherence.readableSourceIds.size())},
                {"message", "Fewer than two kernel release sources were readable; the identity "
                            "comparison could not run."}};
            for (const auto& source : identity["sources"]) {
                if (source["readable"].get<bool>()) {
                    entry[source["source"].get<std::string>()] = source["value"];
                }
            }
            payload["collectionErrors"].push_back(entry);
        }

        payload["hitCount"] = hitCount;

        const DetectionAssessment assessment = kernel_identity::assessKernelCheck(
            {.postureHitCount = hitCount,
             .coherence = coherence.state,
             .anyPostureSourceReadable =
                 kallsymsReadable || !procVersion.empty() || !cmdline.empty() || unameOk});

        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "KERNEL_CHECK"; }
};

REGISTER_DETECTION(KernelCheckDetection);

}  // namespace tamperprobe
