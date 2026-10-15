//
// TEE Certificate Parser - adapted from Overt (zTee.cpp)
//

#include "tee_cert_parser.h"

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <string>
#include <vector>

#include "../../common/log.h"

// TEE attestation extension OID
#define TEE_ATTESTATION_OID "1.3.6.1.4.1.11129.2.1.17"

// ASN.1 tag constants
#define ASN1_UNIVERSAL 0x00
#define ASN1_APPLICATION 0x40
#define ASN1_CONTEXT_SPECIFIC 0x80
#define ASN1_PRIVATE 0xC0

#define ASN1_CONSTRUCTED 0x20
#define ASN1_PRIMITIVE 0x00

#define ASN1_BOOLEAN 0x01
#define ASN1_INTEGER 0x02
#define ASN1_BIT_STRING 0x03
#define ASN1_OCTET_STRING_TAG 0x04
#define ASN1_NULL 0x05
#define ASN1_OBJECT_IDENTIFIER 0x06
#define ASN1_ENUMERATED 0x0A
#define ASN1_UTF8_STRING 0x0C
#define ASN1_SEQUENCE 0x10
#define ASN1_SET 0x11
#define ASN1_NUMERIC_STRING 0x12
#define ASN1_PRINTABLE_STRING 0x13
#define ASN1_T61_STRING 0x14
#define ASN1_VIDEOTEX_STRING 0x15
#define ASN1_IA5_STRING 0x16
#define ASN1_UTC_TIME 0x17
#define ASN1_GENERALIZED_TIME 0x18
#define ASN1_GRAPHIC_STRING 0x19
#define ASN1_VISIBLE_STRING 0x1A
#define ASN1_GENERAL_STRING 0x1B
#define ASN1_UNIVERSAL_STRING 0x1C
#define ASN1_BMP_STRING 0x1E

#define ASN1_CONSTRUCTED_SEQUENCE (ASN1_CONSTRUCTED | ASN1_SEQUENCE)

// Keymaster tags
#define KEYMASTER_TAG_TYPE_MASK 0x0000FF00
#define KM_TAG_ROOT_OF_TRUST 0x000002C0

// Verified boot states
#define VERIFIED_BOOT_STATE_VERIFIED 0
#define VERIFIED_BOOT_STATE_SELF_SIGNED 1
#define VERIFIED_BOOT_STATE_UNVERIFIED 2
#define VERIFIED_BOOT_STATE_FAILED 3

// ASN.1 object structure
typedef struct {
    int tag;
    int tag_class;
    int is_constructed;
    int tag_no;
    int length;
    const unsigned char* data;
    int data_len;
} asn1_object_t;

// Forward declarations
static int parse_asn1_tag(const unsigned char* data, int len, int* offset, asn1_object_t* obj);
static int parse_asn1_length(const unsigned char* data, int len, int* offset);
static int parse_asn1_tag_number(const unsigned char* data, int len, int* offset, int tag);
static int parse_x509_certificate(const unsigned char* data, int len, tee_info_t* tee_info);
static int parse_attestation_record(const unsigned char* data, int len, tee_info_t* tee_info);
static int find_root_of_trust_in_authorization_list(const unsigned char* data, int len, root_of_trust_t* root_of_trust);
static int parse_root_of_trust_sequence(const unsigned char* data, int len, root_of_trust_t* root_of_trust);
static void print_hex_data(const char* prefix, const unsigned char* data, int len, const char* suffix);
static void copy_octets(const unsigned char* source, int source_len, unsigned char* target,
                        int target_capacity, int* target_len, char* target_hex,
                        int target_hex_capacity);

// Get extension by OID using manual ASN.1 parsing
static int get_extension_by_oid_manual(const unsigned char* data, int len, const char* oid_str,
                                       unsigned char** ext_data, int* ext_len) {
    *ext_data = NULL;
    *ext_len = 0;

    if (!data || len <= 0) {
        LOGE("get_extension_by_oid_manual: invalid parameters");
        return -1;
    }

    int offset = 0;
    asn1_object_t obj;

    while (offset < len) {
        if (parse_asn1_tag(data, len, &offset, &obj) != 0) {
            LOGE("get_extension_by_oid_manual: failed to parse tag at offset %d", offset);
            break;
        }

        if ((obj.tag & 0x1F) == ASN1_SEQUENCE && obj.is_constructed) {
            int ext_offset = 0;
            asn1_object_t ext_obj;

            while (ext_offset < obj.data_len) {
                asn1_object_t extension_sequence;
                if (parse_asn1_tag(obj.data, obj.data_len, &ext_offset, &extension_sequence) != 0) {
                    LOGE("get_extension_by_oid_manual: failed to parse extension sequence");
                    break;
                }

                int seq_offset = 0;
                if (parse_asn1_tag(extension_sequence.data, extension_sequence.data_len, &seq_offset, &ext_obj) != 0) {
                    LOGE("get_extension_by_oid_manual: failed to parse extension OID");
                    ext_offset += extension_sequence.length;
                    continue;
                }

                if (ext_obj.tag == ASN1_OBJECT_IDENTIFIER) {
                    if (ext_obj.data_len == 10) {
                        if (ext_obj.data[0] == 0x2B && ext_obj.data[1] == 0x06 && ext_obj.data[2] == 0x01 &&
                            ext_obj.data[3] == 0x04 && ext_obj.data[4] == 0x01 && ext_obj.data[5] == 0xD6 &&
                            ext_obj.data[6] == 0x79 && ext_obj.data[7] == 0x02 && ext_obj.data[8] == 0x01 &&
                            ext_obj.data[9] == 0x11) {
                            if (seq_offset < extension_sequence.data_len) {
                                asn1_object_t critical_obj;
                                if (parse_asn1_tag(extension_sequence.data, extension_sequence.data_len, &seq_offset,
                                                   &critical_obj) == 0) {
                                    if (critical_obj.tag == ASN1_BOOLEAN) {
                                        // Continue to parse the extension value (third element)
                                    } else {
                                        if (critical_obj.tag == ASN1_OCTET_STRING_TAG) {
                                            *ext_data = (unsigned char*)critical_obj.data;
                                            *ext_len = critical_obj.data_len;
                                            return 0;
                                        }
                                        return -1;
                                    }
                                }
                            }

                            if (seq_offset < extension_sequence.data_len) {
                                if (parse_asn1_tag(extension_sequence.data, extension_sequence.data_len, &seq_offset,
                                                   &ext_obj) == 0) {
                                    if (ext_obj.tag == ASN1_OCTET_STRING_TAG) {
                                        *ext_data = (unsigned char*)ext_obj.data;
                                        *ext_len = ext_obj.data_len;
                                        return 0;
                                    }
                                    return -1;
                                }
                            }

                            LOGE("Failed to parse extension value for OID %s", oid_str);
                            return -1;
                        }
                    }
                }
            }
        }

        offset += obj.length;
    }

    return -1;
}

static void print_hex_data(const char* prefix, const unsigned char* data, int len, const char* suffix) {
    if (len <= 0) {
        LOGE("%s: empty data%s", prefix, suffix ? suffix : "");
        return;
    }

    int max_per_line = 32;
    int lines = (len + max_per_line - 1) / max_per_line;

    for (int line = 0; line < lines; line++) {
        int start = line * max_per_line;
        int end = (start + max_per_line < len) ? start + max_per_line : len;

        char hex_buf[256] = {0};
        int pos = 0;

        pos += snprintf(hex_buf + pos, sizeof(hex_buf) - pos, "%s[%d-%d]: ", prefix, start, end - 1);

        for (int i = start; i < end; i++) {
            pos += snprintf(hex_buf + pos, sizeof(hex_buf) - pos, "0x%02x", data[i]);
            if (i < end - 1) {
                pos += snprintf(hex_buf + pos, sizeof(hex_buf) - pos, ", ");
            }
        }

        if (suffix) {
            pos += snprintf(hex_buf + pos, sizeof(hex_buf) - pos, "%s", suffix);
        }

        LOGV("%s", hex_buf);
    }
}

static int parse_asn1_object(const unsigned char* data, int len, int* offset, const unsigned char** object_data,
                             int* object_len) {
    if (*offset >= len) {
        return -1;
    }

    int tag = data[*offset];
    (*offset)++;

    int tag_no = tag & 0x1f;

    if (*offset >= len) {
        return -1;
    }

    int length = data[*offset];
    (*offset)++;

    if ((length >> 7) == 0) {
        // short form
    } else if (length == 0x80) {
        return -1;
    } else {
        int octets_count = length & 0x7F;
        length = 0;

        for (int i = 0; i < octets_count; i++) {
            if (*offset >= len) {
                return -1;
            }

            if ((length >> 23) != 0) {
                return -1;
            }

            int octet = data[*offset];
            (*offset)++;

            length = (length << 8) + octet;
        }
    }

    if (*offset + length > len) {
        return -1;
    }

    *object_data = data + *offset;
    *object_len = length;
    *offset += length;

    return tag;
}

static int parse_asn1_tag_number(const unsigned char* data, int len, int* offset, int tag) {
    int tag_no = tag & 0x1f;

    if (tag_no == 0x1f) {
        if (*offset >= len) {
            return -1;
        }

        int b = data[*offset];
        (*offset)++;

        if (b < 31) {
            return -1;
        }

        tag_no = b & 0x7f;

        if (tag_no == 0) {
            return -1;
        }

        while ((b & 0x80) != 0) {
            if ((tag_no >> 24) != 0) {
                return -1;
            }

            tag_no <<= 7;

            if (*offset >= len) {
                return -1;
            }

            b = data[*offset];
            (*offset)++;

            tag_no |= (b & 0x7f);
        }
    }

    return tag_no;
}

static int parse_asn1_length(const unsigned char* data, int len, int* offset) {
    if (*offset >= len) {
        return -1;
    }

    int length = data[*offset];
    (*offset)++;

    if ((length >> 7) == 0) {
        return length;
    }

    if (length == 0x80) {
        return -1;
    }

    if (length < 0) {
        return -1;
    }

    int octets_count = length & 0x7F;
    length = 0;

    for (int i = 0; i < octets_count; i++) {
        if (*offset >= len) {
            return -1;
        }

        if ((length >> 23) != 0) {
            return -1;
        }

        int octet = data[*offset];
        (*offset)++;

        length = (length << 8) | octet;
    }

    return length;
}

static int parse_asn1_tag(const unsigned char* data, int len, int* offset, asn1_object_t* obj) {
    if (*offset >= len) {
        return -1;
    }

    int tag = data[*offset];
    (*offset)++;

    obj->tag = tag;
    obj->tag_class = tag & 0xE0;
    obj->is_constructed = (tag & 0x20) != 0;

    int tag_no = parse_asn1_tag_number(data, len, offset, tag);
    if (tag_no < 0) {
        return -1;
    }

    obj->tag_no = tag_no;

    int length = parse_asn1_length(data, len, offset);
    if (length < 0) {
        return -1;
    }

    obj->length = length;
    obj->data = data + *offset;
    obj->data_len = length;

    *offset += length;

    return 0;
}

static int parse_x509_certificate(const unsigned char* data, int len, tee_info_t* tee_info) {
    int offset = 0;
    const unsigned char* cert_data;
    int cert_len;

    int tag = parse_asn1_object(data, len, &offset, &cert_data, &cert_len);
    if (tag != ASN1_CONSTRUCTED_SEQUENCE) {
        LOGE("Expected certificate sequence, got tag: 0x%02x", tag);
        return -1;
    }

    const unsigned char* body_data;
    int body_len;
    int body_offset = 0;

    tag = parse_asn1_object(cert_data, cert_len, &body_offset, &body_data, &body_len);
    if (tag != ASN1_CONSTRUCTED_SEQUENCE) {
        LOGE("Expected certificate body sequence, got tag: 0x%02x", tag);
        return -1;
    }

    for (int i = 0; i < 6; i++) {
        const unsigned char* element_data;
        int element_len;
        int element_offset = 0;

        tag = parse_asn1_object(body_data, body_len, &element_offset, &element_data, &element_len);
        if (tag < 0) {
            LOGE("Failed to parse element %d", i);
            return -1;
        }

        body_data += element_offset;
        body_len -= element_offset;
    }

    const unsigned char* spki_data;
    int spki_len;
    int spki_offset = 0;

    tag = parse_asn1_object(body_data, body_len, &spki_offset, &spki_data, &spki_len);
    if (tag != ASN1_CONSTRUCTED_SEQUENCE) {
        LOGE("Expected subject public key info sequence, got tag: 0x%02x", tag);
        return -1;
    }

    body_data += spki_offset;
    body_len -= spki_offset;

    if (body_len > 0) {
        const unsigned char* ext_data;
        int ext_len;
        int ext_offset = 0;

        tag = parse_asn1_object(body_data, body_len, &ext_offset, &ext_data, &ext_len);

        if (tag == ASN1_CONSTRUCTED_SEQUENCE || tag == 0xa3) {
            unsigned char* extension_data = NULL;
            int extension_len = 0;

            if (get_extension_by_oid_manual(ext_data, ext_len, TEE_ATTESTATION_OID, &extension_data, &extension_len) ==
                0) {
                tee_info->has_attestation_extension = 1;

                if (parse_attestation_record(extension_data, extension_len, tee_info) != 0) {
                    LOGE("Failed to parse attestation extension");
                    return -1;
                }
            } else {
                tee_info->has_attestation_extension = 0;
            }
        } else {
            tee_info->has_attestation_extension = 0;
        }
    } else {
        tee_info->has_attestation_extension = 0;
    }

    return 0;
}

static int parse_attestation_record(const unsigned char* data, int len, tee_info_t* tee_info) {
    int offset = 0;
    asn1_object_t obj;

    if (parse_asn1_tag(data, len, &offset, &obj) != 0) {
        LOGE("Failed to parse attestation sequence");
        return -1;
    }

    if ((obj.tag & 0x1F) != ASN1_SEQUENCE || !obj.is_constructed) {
        LOGE("Expected attestation sequence, got tag=0x%02x", obj.tag);
        return -1;
    }

    int att_offset = 0;
    asn1_object_t att_obj;

    if (parse_asn1_tag(obj.data, obj.data_len, &att_offset, &att_obj) != 0) {
        LOGE("Failed to parse attestation version");
        return -1;
    }
    if ((att_obj.tag == ASN1_INTEGER || att_obj.tag == ASN1_ENUMERATED) &&
        att_obj.data_len > 0) {
        tee_info->attestation_version = parse_asn1_integer(att_obj.data, att_obj.data_len);
    }

    if (parse_asn1_tag(obj.data, obj.data_len, &att_offset, &att_obj) != 0) {
        LOGE("Failed to parse security level");
        return -1;
    }

    if ((att_obj.tag == ASN1_INTEGER || att_obj.tag == ASN1_ENUMERATED) && att_obj.data_len > 0) {
        tee_info->security_level = parse_asn1_integer(att_obj.data, att_obj.data_len);
    }

    if (parse_asn1_tag(obj.data, obj.data_len, &att_offset, &att_obj) != 0) {
        LOGE("Failed to parse keymaster version");
        return -1;
    }
    if ((att_obj.tag == ASN1_INTEGER || att_obj.tag == ASN1_ENUMERATED) &&
        att_obj.data_len > 0) {
        tee_info->keymaster_version = parse_asn1_integer(att_obj.data, att_obj.data_len);
    }

    if (parse_asn1_tag(obj.data, obj.data_len, &att_offset, &att_obj) != 0) {
        LOGE("Failed to parse keymaster security level");
        return -1;
    }
    if ((att_obj.tag == ASN1_INTEGER || att_obj.tag == ASN1_ENUMERATED) &&
        att_obj.data_len > 0) {
        tee_info->keymaster_security_level =
                parse_asn1_integer(att_obj.data, att_obj.data_len);
    }

    if (parse_asn1_tag(obj.data, obj.data_len, &att_offset, &att_obj) != 0) {
        LOGE("Failed to parse attestation challenge");
        return -1;
    }
    if (att_obj.tag != ASN1_OCTET_STRING_TAG ||
        att_obj.data_len > static_cast<int>(sizeof(tee_info->attestation_challenge))) {
        LOGE("Invalid attestation challenge");
        return -1;
    }
    tee_info->attestation_challenge_len = att_obj.data_len;
    if (att_obj.data_len > 0) {
        memcpy(tee_info->attestation_challenge, att_obj.data, att_obj.data_len);
    }

    if (parse_asn1_tag(obj.data, obj.data_len, &att_offset, &att_obj) != 0) {
        LOGE("Failed to parse unique ID");
        return -1;
    }

    if (parse_asn1_tag(obj.data, obj.data_len, &att_offset, &att_obj) != 0) {
        LOGE("Failed to parse software enforced list");
        return -1;
    }

    if ((att_obj.tag & 0x1F) == ASN1_SEQUENCE && att_obj.is_constructed) {
        find_root_of_trust_in_authorization_list(att_obj.data, att_obj.data_len, &tee_info->root_of_trust);
    }

    if (parse_asn1_tag(obj.data, obj.data_len, &att_offset, &att_obj) != 0) {
        LOGE("Failed to parse tee enforced list");
        return -1;
    }

    if ((att_obj.tag & 0x1F) == ASN1_SEQUENCE && att_obj.is_constructed) {
        if (!tee_info->root_of_trust.valid) {
            find_root_of_trust_in_authorization_list(att_obj.data, att_obj.data_len, &tee_info->root_of_trust);
        }
    }

    return 0;
}

static int find_root_of_trust_in_authorization_list(const unsigned char* data, int len,
                                                    root_of_trust_t* root_of_trust) {
    int offset = 0;
    asn1_object_t obj;

    while (offset < len) {
        if (parse_asn1_tag(data, len, &offset, &obj) != 0) {
            break;
        }

        if ((obj.tag & ASN1_CONTEXT_SPECIFIC) && (obj.tag & 0x1F) == 0x1F) {
            if (obj.tag_no == 704) {
                if (parse_root_of_trust_sequence(obj.data, obj.data_len, root_of_trust) == 0) {
                    return 0;
                }
            }
        }
    }

    return -1;
}

static int parse_root_of_trust_sequence(const unsigned char* data, int len, root_of_trust_t* root_of_trust) {
    int offset = 0;
    asn1_object_t obj;

    if (parse_asn1_tag(data, len, &offset, &obj) != 0) {
        LOGE("Failed to parse root of trust sequence");
        return -1;
    }

    if ((obj.tag & 0x1F) != ASN1_SEQUENCE || !obj.is_constructed) {
        LOGE("Expected root of trust sequence, got tag=0x%02x", obj.tag);
        return -1;
    }

    int rot_offset = 0;
    asn1_object_t rot_obj;

    if (parse_asn1_tag(obj.data, obj.data_len, &rot_offset, &rot_obj) != 0) {
        LOGE("Failed to parse verified boot key");
        return -1;
    }

    if (rot_obj.tag == ASN1_OCTET_STRING_TAG) {
        copy_octets(rot_obj.data, rot_obj.data_len, root_of_trust->verified_boot_key,
                    static_cast<int>(sizeof(root_of_trust->verified_boot_key)),
                    &root_of_trust->verified_boot_key_len,
                    root_of_trust->verified_boot_key_hex,
                    static_cast<int>(sizeof(root_of_trust->verified_boot_key_hex)));
    }

    if (parse_asn1_tag(obj.data, obj.data_len, &rot_offset, &rot_obj) != 0) {
        LOGE("Failed to parse device locked");
        return -1;
    }

    if (rot_obj.tag == ASN1_BOOLEAN && rot_obj.data_len > 0) {
        root_of_trust->device_locked = (rot_obj.data[0] != 0);
    }

    if (parse_asn1_tag(obj.data, obj.data_len, &rot_offset, &rot_obj) != 0) {
        LOGE("Failed to parse verified boot state");
        return -1;
    }

    if ((rot_obj.tag == ASN1_INTEGER || rot_obj.tag == ASN1_ENUMERATED) && rot_obj.data_len > 0) {
        root_of_trust->verified_boot_state = rot_obj.data[0];
    }

    if (rot_offset < obj.data_len) {
        if (parse_asn1_tag(obj.data, obj.data_len, &rot_offset, &rot_obj) == 0) {
            if (rot_obj.tag == ASN1_OCTET_STRING_TAG) {
                copy_octets(rot_obj.data, rot_obj.data_len,
                            root_of_trust->verified_boot_hash,
                            static_cast<int>(sizeof(root_of_trust->verified_boot_hash)),
                            &root_of_trust->verified_boot_hash_len,
                            root_of_trust->verified_boot_hash_hex,
                            static_cast<int>(sizeof(root_of_trust->verified_boot_hash_hex)));
            }
        }
    }

    root_of_trust->valid = 1;
    return 0;
}

static void copy_octets(const unsigned char* source, int source_len,
                        unsigned char* target, int target_capacity, int* target_len,
                        char* target_hex, int target_hex_capacity) {
    if (target_len != nullptr) *target_len = 0;
    if (target_hex != nullptr && target_hex_capacity > 0) target_hex[0] = '\0';
    if (source == nullptr || source_len <= 0 || target == nullptr ||
        target_capacity <= 0 || target_len == nullptr || target_hex == nullptr ||
        target_hex_capacity <= 0) {
        return;
    }
    const int maximumHexBytes = (target_hex_capacity - 1) / 2;
    const int maximumBytes = std::min(target_capacity, maximumHexBytes);
    if (source_len > maximumBytes) {
        return;
    }
    const int copied = source_len;
    memcpy(target, source, copied);
    *target_len = copied;
    for (int index = 0; index < copied; ++index) {
        snprintf(target_hex + index * 2, target_hex_capacity - index * 2,
                 "%02x", source[index]);
    }
    target_hex[copied * 2] = '\0';
}

void bytes_to_hex(const unsigned char* data, int len, char* hex_str) {
    for (int i = 0; i < len; i++) {
        sprintf(hex_str + i * 2, "%02x", data[i]);
    }
    hex_str[len * 2] = '\0';
}

int parse_tee_certificate(const unsigned char* cert_data, int cert_len, tee_info_t* tee_info) {
    if (!cert_data || !tee_info || cert_len <= 0) {
        LOGE("Invalid parameters");
        return -1;
    }

    memset(tee_info, 0, sizeof(tee_info_t));

    if (parse_x509_certificate(cert_data, cert_len, tee_info) != 0) {
        LOGE("Failed to parse X.509 certificate");
        return -1;
    }

    return 0;
}

int parse_asn1_integer(const unsigned char* data, int len) {
    if (len <= 0) return 0;

    int result = 0;
    int sign = 1;

    if (data[0] & 0x80) {
        sign = -1;
    }

    for (int i = 0; i < len; i++) {
        result = (result << 8) | data[i];
    }

    if (sign == -1) {
        result = -(~(result - 1));
    }

    return result;
}

int get_tee_security_level(const tee_info_t* tee_info) {
    if (!tee_info) {
        return -1;
    }
    return tee_info->security_level;
}

int get_tee_root_of_trust(const tee_info_t* tee_info, root_of_trust_t* root_of_trust) {
    if (!tee_info || !root_of_trust) {
        return -1;
    }
    if (!tee_info->root_of_trust.valid) {
        return -1;
    }
    *root_of_trust = tee_info->root_of_trust;
    return 0;
}

int check_tee_security_status(const tee_info_t* tee_info, int* device_locked, int* verified_boot_state) {
    if (!tee_info || !device_locked || !verified_boot_state) {
        return -1;
    }
    if (!tee_info->root_of_trust.valid) {
        return -1;
    }
    *device_locked = tee_info->root_of_trust.device_locked;
    *verified_boot_state = tee_info->root_of_trust.verified_boot_state;
    return 0;
}

int has_tee_attestation_extension(const tee_info_t* tee_info) {
    if (!tee_info) {
        return 0;
    }
    return tee_info->has_attestation_extension ? 1 : 0;
}

static bool encode_oid(const char* oid, std::vector<unsigned char>& out) {
    if (!oid || !*oid) {
        return false;
    }

    std::vector<int> parts;
    int value = 0;
    for (const char* p = oid;; ++p) {
        if (*p >= '0' && *p <= '9') {
            value = value * 10 + (*p - '0');
        } else if (*p == '.' || *p == '\0') {
            parts.push_back(value);
            value = 0;
            if (*p == '\0') break;
        } else {
            return false;
        }
    }

    if (parts.size() < 2) {
        return false;
    }

    out.clear();
    out.push_back(static_cast<unsigned char>(parts[0] * 40 + parts[1]));

    for (size_t i = 2; i < parts.size(); ++i) {
        unsigned int v = static_cast<unsigned int>(parts[i]);
        unsigned char tmp[5];
        int tmp_len = 0;

        do {
            tmp[tmp_len++] = static_cast<unsigned char>(v & 0x7F);
            v >>= 7;
        } while (v > 0);

        for (int j = tmp_len - 1; j >= 0; --j) {
            unsigned char b = tmp[j];
            if (j != 0) {
                b |= 0x80;
            }
            out.push_back(b);
        }
    }

    return true;
}

int compare_oid(const unsigned char* data, int len, const char* oid) {
    if (!data || !oid || len <= 0) {
        return -1;
    }

    std::vector<unsigned char> encoded;
    if (!encode_oid(oid, encoded)) {
        return -1;
    }

    if (static_cast<int>(encoded.size()) != len) {
        return -1;
    }

    return (memcmp(data, encoded.data(), len) == 0) ? 0 : -1;
}
