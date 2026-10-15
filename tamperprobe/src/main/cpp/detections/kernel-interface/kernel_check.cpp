#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <sys/utsname.h>

#include <set>

#include "../../common/io_utils.h"
#include "../../core/detection.h"
#include "../../core/detection_registry.h"
#include "../../nlohmann/json.hpp"

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
        "arter97", "franco", "elementalx", "blu_spark", "sultan",
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

}  // namespace

/**
 * Kernel-level integrity checks:
 * 1. kptr_restrict check: parse first 20 lines of /proc/kallsyms (>50% non-zero -> SIGNAL)
 * 2. /proc/version and uname signature scan (CJK, emoji, t.me/, @ mentions, custom kernel tags -> MODERATE SIGNAL)
 * 3. Bootloader state and kernel parameters from /proc/cmdline
 *
 * References: Duck-Detector kernelcheck/native_bridge.cpp & KernelCheckRepository.kt
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
        for (const std::string& token : symbolMatches) {
            hitCount++;
            nlohmann::json f;
            f["check"] = "kernel_symbol_token";
            f["marker"] = "root_symbol";
            f["value"] = token;
            f["detail"] = "Root-framework symbol token present in kernel symbols or banner: " + token;
            payload["findings"].push_back(f);
        }

        // Honest availability. Three of this detector's sub-checks read files that an app
        // cannot open on current Android: kallsyms (the kptr and symbol checks), modules
        // (the symbol check), and cmdline (the bootloader-state check). When they are
        // unavailable a not-found is not a clean answer, so each unreadable source is
        // recorded as a collection issue, which marks the unit PARTIAL. The uname banner
        // scan is always available and its result stands. The detector still reports
        // NOT_OBSERVED rather than INCONCLUSIVE, because that live sub-check did answer.
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

        payload["hitCount"] = hitCount;

        DetectionAssessment assessment = DetectionAssessment::notObserved();
        if (hitCount >= 2) {
            assessment = DetectionAssessment::strongObserved();
        } else if (hitCount > 0) {
            assessment = DetectionAssessment::moderateObserved();
        } else if (!kallsymsReadable && procVersion.empty() && cmdline.empty() && !unameOk) {
            assessment = DetectionAssessment::inconclusive();
        }

        return {assessment, payload.dump()};
    }

    const char* getId() const override { return "KERNEL_CHECK"; }
};

REGISTER_DETECTION(KernelCheckDetection);

}  // namespace tamperprobe
