#ifndef TAMPERPROBE_PROPERTY_AREA_PARSER_H
#define TAMPERPROBE_PROPERTY_AREA_PARSER_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace tamperprobe {

enum class PropertyAreaStatus {
    PARSED,
    UNAVAILABLE,
    INVALID,
    UNSUPPORTED,
};

struct PropertyAreaRange {
    std::uint32_t offset = 0;
    std::uint32_t length = 0;
};

struct PropertyEntryDetail {
    std::string name;
    std::string value;
    std::uint32_t serial = 0;
    std::uint32_t valueLengthFromSerial = 0;
    std::size_t stringLength = 0;
    bool isLongProperty = false;
    bool isReadOnly = false;
    // Set while bionic is mid-update on this property. Its serial and value are
    // legitimately inconsistent in that window, so length checks must skip it.
    bool isDirty = false;
    bool hasTrailingBytes = false;
    std::size_t trailingBytesCount = 0;
    std::string trailingBytesSnippet;
};

struct PropertyAreaRecord {
    std::string path;
    std::string context;
    PropertyAreaStatus status = PropertyAreaStatus::UNAVAILABLE;
    std::string error;
    int errorNumber = 0;
    std::uint32_t magic = 0;
    std::uint32_t version = 0;
    std::uint32_t bytesUsed = 0;
    std::uint32_t referencedBytes = 0;
    std::uint32_t unreferencedBytes = 0;
    std::vector<PropertyAreaRange> unreferencedRanges;
    std::map<std::string, std::string> properties;
    std::vector<PropertyEntryDetail> propertyDetails;
};

const char* propertyAreaStatusName(PropertyAreaStatus status);

PropertyAreaRecord parsePropertyAreaBuffer(const std::uint8_t* bytes, std::size_t size,
                                           const std::string& path,
                                           const std::string& context);

std::vector<PropertyAreaRecord> scanPropertyAreas();

}  // namespace tamperprobe

#endif  // TAMPERPROBE_PROPERTY_AREA_PARSER_H
