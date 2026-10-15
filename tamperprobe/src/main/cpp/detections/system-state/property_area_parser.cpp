#include "property_area_parser.h"

#include <set>
#include <cstdio>
#include <array>
#include <dirent.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <unordered_set>
#include <utility>

namespace tamperprobe {
namespace {

constexpr char kPropertyDirectory[] = "/dev/__properties__";
constexpr std::uint32_t kPropertyAreaMagic = 0x504f5250U;
constexpr std::uint32_t kPropertyAreaVersion = 0xfc6ed0abU;
constexpr std::uint32_t kLongPropertyFlag = 1U << 16;
constexpr std::size_t kHeaderSize = 128;
constexpr std::size_t kAlignment = 4;

#ifdef O_NOFOLLOW
constexpr int kOpenFlags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
#else
constexpr int kOpenFlags = O_RDONLY | O_CLOEXEC;
#endif

struct PropertyAreaHeader {
    std::uint32_t bytesUsed;
    std::uint32_t serial;
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t reserved[28];
};

struct PropertyTrieNode {
    std::uint32_t nameLength;
    std::uint32_t propertyOffset;
    std::uint32_t leftOffset;
    std::uint32_t rightOffset;
    std::uint32_t childrenOffset;
};

struct LongPropertyReference {
    char legacyError[56];
    std::uint32_t offset;
};

struct PropertyInfo {
    std::uint32_t serial;
    union {
        char value[PROP_VALUE_MAX];
        LongPropertyReference longProperty;
    };
};

static_assert(sizeof(PropertyAreaHeader) == kHeaderSize, "Unexpected property-area header size");
static_assert(sizeof(PropertyInfo) == 96, "Unexpected property-info size");

// Properties whose value is a device identifier. Their residue is never emitted.
bool isIdentifierProperty(const std::string& name) {
    static const char* kIdentifierNames[] = {
        "ro.serialno", "ro.boot.serialno", "ro.ril.oem.imei", "ro.ril.oem.meid",
        "ro.boot.cid", "ro.boot.wifimacaddr", "ro.boot.btmacaddr",
    };
    for (const char* candidate : kIdentifierNames) {
        if (name == candidate) return true;
    }
    return name.find("serialno") != std::string::npos ||
           name.find("imei") != std::string::npos ||
           name.find("macaddr") != std::string::npos;
}

std::size_t alignUp(std::size_t value) {
    return (value + kAlignment - 1) & ~(kAlignment - 1);
}

bool isSkippedEntry(const char* name) {
    return name == nullptr || strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
           strcmp(name, "properties_serial") == 0 || strcmp(name, "property_info") == 0;
}

std::string contextFromPath(const std::string& path) {
    const std::size_t separator = path.find_last_of('/');
    return separator == std::string::npos ? path : path.substr(separator + 1);
}

class PropertyAreaParser {
   public:
    PropertyAreaParser(const std::uint8_t* data, std::size_t bytesUsed,
                       PropertyAreaRecord& record)
        : data_(data), bytesUsed_(bytesUsed), occupied_(bytesUsed, false), record_(record) {}

    bool parse() {
        const PropertyTrieNode* root = objectAt<PropertyTrieNode>(0);
        if (root == nullptr || root->nameLength != 0) {
            return fail("invalid trie root");
        }
        if (!markRange(0, sizeof(PropertyTrieNode), "trie root") ||
            !markRange(sizeof(PropertyTrieNode), PROP_VALUE_MAX, "dirty backup area")) {
            return false;
        }
        if (!boundedString(sizeof(PropertyTrieNode), PROP_VALUE_MAX).first) {
            return fail("dirty backup area is not NUL-terminated");
        }
        if (!visitTree(root->leftOffset, "") || !visitTree(root->rightOffset, "") ||
            !visitTree(root->childrenOffset, "") ||
            !visitProperty(root->propertyOffset, "")) {
            return false;
        }
        collectUnreferencedRanges();
        return true;
    }

   private:
    template <typename T>
    const T* objectAt(std::uint32_t offset) const {
        if (offset > bytesUsed_ || sizeof(T) > bytesUsed_ - offset) return nullptr;
        return reinterpret_cast<const T*>(data_ + offset);
    }

    std::pair<bool, std::string> boundedString(std::uint32_t offset,
                                               std::size_t maximum) const {
        if (offset >= bytesUsed_) return {false, {}};
        const std::size_t available = std::min(maximum, bytesUsed_ - offset);
        const void* terminator = memchr(data_ + offset, '\0', available);
        if (terminator == nullptr) return {false, {}};
        const auto* end = static_cast<const std::uint8_t*>(terminator);
        return {true, std::string(reinterpret_cast<const char*>(data_ + offset),
                                  static_cast<std::size_t>(end - (data_ + offset)))};
    }

    bool markRange(std::size_t offset, std::size_t length, const char* label) {
        if (offset % kAlignment != 0 || length % kAlignment != 0 ||
            offset > bytesUsed_ || length > bytesUsed_ - offset) {
            return fail(std::string(label) + " is out of bounds or misaligned");
        }
        for (std::size_t index = offset; index < offset + length; ++index) {
            if (occupied_[index]) return fail(std::string(label) + " overlaps another allocation");
            occupied_[index] = true;
        }
        return true;
    }

    bool visitTree(std::uint32_t offset, const std::string& parentName) {
        if (offset == 0) return true;
        if (!visitedNodes_.insert(offset).second) return fail("trie cycle or shared node detected");

        const PropertyTrieNode* node = objectAt<PropertyTrieNode>(offset);
        if (node == nullptr) return fail("trie node offset is out of bounds");
        if (node->nameLength == 0 || node->nameLength > bytesUsed_) {
            return fail("trie node has an invalid name length");
        }
        const std::uint32_t nameOffset = offset + sizeof(PropertyTrieNode);
        if (nameOffset < offset) return fail("trie node name offset overflow");
        const auto name = boundedString(nameOffset, bytesUsed_ - nameOffset);
        if (!name.first || name.second.size() != node->nameLength) {
            return fail("trie node name is invalid");
        }
        const std::size_t allocation = alignUp(sizeof(PropertyTrieNode) + name.second.size() + 1);
        if (!markRange(offset, allocation, "trie node")) return false;

        const std::string fullName = parentName.empty() ? name.second : parentName + "." + name.second;
        return visitTree(node->leftOffset, parentName) &&
               visitTree(node->rightOffset, parentName) &&
               visitTree(node->childrenOffset, fullName) &&
               visitProperty(node->propertyOffset, fullName);
    }

    bool visitProperty(std::uint32_t offset, const std::string& trieName) {
        if (offset == 0) return true;
        if (!visitedProperties_.insert(offset).second) {
            return fail("property allocation is referenced more than once");
        }
        const PropertyInfo* property = objectAt<PropertyInfo>(offset);
        if (property == nullptr) return fail("property offset is out of bounds");

        const std::uint32_t nameOffset = offset + sizeof(PropertyInfo);
        if (nameOffset < offset) return fail("property name offset overflow");
        const auto name = boundedString(nameOffset, bytesUsed_ - nameOffset);
        if (!name.first || name.second.empty() || (!trieName.empty() && name.second != trieName)) {
            return fail("property name does not match its trie path");
        }
        const std::size_t allocation = alignUp(sizeof(PropertyInfo) + name.second.size() + 1);
        if (!markRange(offset, allocation, "property")) return false;

        std::string value;
        PropertyEntryDetail detail;
        detail.name = name.second;
        detail.serial = property->serial;
        detail.isReadOnly = (name.second.rfind("ro.", 0) == 0);

        if ((property->serial & kLongPropertyFlag) != 0) {
            detail.isLongProperty = true;
            const std::uint32_t relativeOffset = property->longProperty.offset;
            if (relativeOffset < sizeof(PropertyInfo) || offset >
                    std::numeric_limits<std::uint32_t>::max() - relativeOffset) {
                return fail("long property value offset is invalid");
            }
            const std::uint32_t valueOffset = offset + relativeOffset;
            const auto longValue = boundedString(valueOffset, bytesUsed_ - valueOffset);
            if (!longValue.first) return fail("long property value is not NUL-terminated");
            const std::size_t valueAllocation = alignUp(longValue.second.size() + 1);
            if (!markRange(valueOffset, valueAllocation, "long property value")) return false;
            value = longValue.second;
            detail.value = value;
            detail.stringLength = value.size();
            detail.valueLengthFromSerial = (property->serial >> 24) & 0xff;
        } else if ((property->serial & 1U) != 0) {
            detail.isDirty = true;
            const auto backup = boundedString(sizeof(PropertyTrieNode), PROP_VALUE_MAX);
            if (!backup.first) return fail("dirty property backup is invalid");
            value = backup.second;
            detail.value = value;
            detail.stringLength = value.size();
            detail.valueLengthFromSerial = (property->serial >> 24) & 0xff;
        } else {
            const auto shortValue = boundedString(offset + sizeof(std::uint32_t), PROP_VALUE_MAX);
            if (!shortValue.first) return fail("short property value is not NUL-terminated");
            value = shortValue.second;
            detail.value = value;
            detail.stringLength = value.size();
            detail.valueLengthFromSerial = (property->serial >> 24) & 0xff;

            // Inspect trailing bytes in value buffer after string NUL terminator
            const auto* valBuf = data_ + offset + sizeof(std::uint32_t);
            std::size_t nonZeroCount = 0;
            std::string snippet;
            for (std::size_t i = detail.stringLength + 1; i < PROP_VALUE_MAX; ++i) {
                if (valBuf[i] != 0) {
                    nonZeroCount++;
                    if (snippet.size() < 16) {
                        const char c = static_cast<char>(valBuf[i]);
                        if (c >= 32 && c <= 126) {
                            snippet.push_back(c);
                        } else {
                            snippet.push_back('.');
                        }
                    }
                }
            }
            if (nonZeroCount > 0) {
                detail.hasTrailingBytes = true;
                detail.trailingBytesCount = nonZeroCount;
                // Residue is a fragment of this property's previous value. For
                // identifier-bearing properties that fragment can be the real device
                // identifier, which must never be retained, so only the count survives.
                detail.trailingBytesSnippet =
                    isIdentifierProperty(name.second) ? std::string("[redacted]") : snippet;
            }
        }
        record_.properties[name.second] = value;
        record_.propertyDetails.push_back(std::move(detail));
        return true;
    }

    void collectUnreferencedRanges() {
        std::size_t index = 0;
        while (index < occupied_.size()) {
            if (occupied_[index]) {
                ++index;
                continue;
            }
            const std::size_t start = index;
            while (index < occupied_.size() && !occupied_[index]) ++index;
            const std::size_t length = index - start;
            record_.unreferencedRanges.push_back(
                {static_cast<std::uint32_t>(start), static_cast<std::uint32_t>(length)});
            record_.unreferencedBytes += static_cast<std::uint32_t>(length);
        }
        record_.referencedBytes = record_.bytesUsed - record_.unreferencedBytes;
    }

    bool fail(std::string error) {
        record_.error = std::move(error);
        return false;
    }

    const std::uint8_t* data_;
    std::size_t bytesUsed_;
    std::vector<bool> occupied_;
    PropertyAreaRecord& record_;
    std::unordered_set<std::uint32_t> visitedNodes_;
    std::unordered_set<std::uint32_t> visitedProperties_;
};

PropertyAreaRecord unavailableRecord(const std::string& path, const std::string& context,
                                     const char* message, int errorNumber) {
    PropertyAreaRecord record;
    record.path = path;
    record.context = context;
    record.status = PropertyAreaStatus::UNAVAILABLE;
    record.error = message;
    record.errorNumber = errorNumber;
    return record;
}

PropertyAreaRecord scanPropertyAreaFile(const std::string& path, const std::string& context) {
    const int descriptor = open(path.c_str(), kOpenFlags);
    if (descriptor < 0) return unavailableRecord(path, context, strerror(errno), errno);

    struct stat status {};
    if (fstat(descriptor, &status) != 0) {
        const int errorNumber = errno;
        close(descriptor);
        return unavailableRecord(path, context, strerror(errorNumber), errorNumber);
    }
    if (!S_ISREG(status.st_mode) || status.st_uid != 0 || status.st_gid != 0 ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(descriptor);
        PropertyAreaRecord record = unavailableRecord(path, context,
                                                       "property-area ownership or mode is invalid", 0);
        record.status = PropertyAreaStatus::INVALID;
        return record;
    }
    if (status.st_size < static_cast<off_t>(sizeof(PropertyAreaHeader))) {
        close(descriptor);
        PropertyAreaRecord record = unavailableRecord(path, context, "property-area file is too small", 0);
        record.status = PropertyAreaStatus::INVALID;
        return record;
    }

    const std::size_t fileSize = static_cast<std::size_t>(status.st_size);
    void* mapping = mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, descriptor, 0);
    const int mappingError = errno;
    close(descriptor);
    if (mapping == MAP_FAILED) return unavailableRecord(path, context, strerror(mappingError), mappingError);

    PropertyAreaRecord record = parsePropertyAreaBuffer(
        static_cast<const std::uint8_t*>(mapping), fileSize, path, context);
    munmap(mapping, fileSize);
    return record;
}

}  // namespace

const char* propertyAreaStatusName(PropertyAreaStatus status) {
    switch (status) {
        case PropertyAreaStatus::PARSED: return "parsed";
        case PropertyAreaStatus::UNAVAILABLE: return "unavailable";
        case PropertyAreaStatus::INVALID: return "invalid";
        case PropertyAreaStatus::UNSUPPORTED: return "unsupported";
    }
    return "invalid";
}

PropertyAreaRecord parsePropertyAreaBuffer(const std::uint8_t* bytes, std::size_t size,
                                           const std::string& path,
                                           const std::string& context) {
    PropertyAreaRecord record;
    record.path = path;
    record.context = context;
    record.status = PropertyAreaStatus::INVALID;
    if (bytes == nullptr || size < sizeof(PropertyAreaHeader)) {
        record.error = "property-area header is unavailable";
        return record;
    }

    const auto* header = reinterpret_cast<const PropertyAreaHeader*>(bytes);
    record.magic = header->magic;
    record.version = header->version;
    record.bytesUsed = header->bytesUsed;
    if (header->magic != kPropertyAreaMagic) {
        record.error = "property-area magic is invalid";
        return record;
    }
    if (header->version != kPropertyAreaVersion) {
        record.status = PropertyAreaStatus::UNSUPPORTED;
        record.error = "property-area version is unsupported";
        return record;
    }
    const std::size_t dataSize = size - sizeof(PropertyAreaHeader);
    if (header->bytesUsed > dataSize ||
        header->bytesUsed < sizeof(PropertyTrieNode) + PROP_VALUE_MAX) {
        record.error = "property-area bytes_used is out of bounds";
        return record;
    }

    PropertyAreaParser parser(bytes + sizeof(PropertyAreaHeader), header->bytesUsed, record);
    if (!parser.parse()) return record;
    record.status = PropertyAreaStatus::PARSED;
    return record;
}

namespace {

// Listing /dev/__properties__ is denied to untrusted_app on current Android, so an
// SDK cannot enumerate the property areas through the filesystem at all. Bionic has
// already mapped every context file whose properties this process has touched, and
// those mappings are visible in our own address space, so the areas are read from
// there instead. This needs no file permission and observes the same bytes the
// accessor observes.
std::vector<PropertyAreaRecord> scanMappedPropertyAreas() {
    std::vector<PropertyAreaRecord> records;
    std::FILE* maps = std::fopen("/proc/self/maps", "r");
    if (maps == nullptr) return records;

    std::set<std::string> seenPaths;
    std::array<char, 1024> line{};
    while (std::fgets(line.data(), static_cast<int>(line.size()), maps) != nullptr) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char permissions[8] = {};
        int pathOffset = 0;
        if (std::sscanf(line.data(), "%llx-%llx %7s %*x %*s %*u %n", &start, &end,
                        permissions, &pathOffset) < 3) {
            continue;
        }
        if (pathOffset <= 0 || static_cast<std::size_t>(pathOffset) >= std::strlen(line.data())) {
            continue;
        }
        if (permissions[0] != 'r') continue;

        std::string path(line.data() + pathOffset);
        while (!path.empty() && (path.back() == '\n' || path.back() == ' ')) path.pop_back();
        if (path.rfind(std::string(kPropertyDirectory) + "/", 0) != 0) continue;
        // property_info and properties_serial live in the same directory but are not
        // property areas, so parsing them yields "magic is invalid" on every device.
        // The directory walk has always skipped them; the mapped scan must too, or a
        // normal device reports a collection error it cannot act on.
        if (isSkippedEntry(contextFromPath(path).c_str())) continue;
        if (!seenPaths.insert(path).second) continue;
        if (end <= start) continue;

        records.push_back(parsePropertyAreaBuffer(reinterpret_cast<const std::uint8_t*>(start),
                                                  static_cast<std::size_t>(end - start), path,
                                                  contextFromPath(path)));
    }
    std::fclose(maps);
    return records;
}

}  // namespace

std::vector<PropertyAreaRecord> scanPropertyAreas() {
    std::vector<PropertyAreaRecord> records = scanMappedPropertyAreas();
    std::set<std::string> seenPaths;
    for (const auto& record : records) seenPaths.insert(record.path);

    // The directory walk still runs where policy allows it, because it also reaches
    // context files this process never touched.
    DIR* directory = opendir(kPropertyDirectory);
    if (directory != nullptr) {
        while (dirent* entry = readdir(directory)) {
            if (isSkippedEntry(entry->d_name)) continue;
            const std::string path = std::string(kPropertyDirectory) + "/" + entry->d_name;
            if (seenPaths.count(path) != 0) continue;
            records.push_back(scanPropertyAreaFile(path, contextFromPath(path)));
        }
        closedir(directory);
    } else if (records.empty()) {
        records.push_back(unavailableRecord(kPropertyDirectory, "directory", strerror(errno), errno));
        return records;
    }

    if (records.empty()) {
        records.push_back(unavailableRecord(kPropertyDirectory, "directory",
                                            "no property-area files were found", 0));
    }
    std::sort(records.begin(), records.end(), [](const auto& left, const auto& right) {
        return left.path < right.path;
    });
    return records;
}

}  // namespace tamperprobe
