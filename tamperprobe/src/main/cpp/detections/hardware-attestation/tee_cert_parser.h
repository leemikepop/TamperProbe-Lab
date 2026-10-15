#ifndef TAMPERPROBE_TEE_CERT_PARSER_H
#define TAMPERPROBE_TEE_CERT_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

// RootOfTrust 結構
typedef struct {
    char verified_boot_key_hex[129];
    char verified_boot_hash_hex[129];
    unsigned char verified_boot_key[64];
    unsigned char verified_boot_hash[64];
    int verified_boot_key_len;
    int verified_boot_hash_len;
    int device_locked;
    int verified_boot_state;
    int valid;
} root_of_trust_t;

// Authorization list
typedef struct {
    root_of_trust_t root_of_trust;
} authorization_list_t;

// TEE info
typedef struct {
    int attestation_version;
    int security_level;
    int keymaster_version;
    int keymaster_security_level;
    unsigned char attestation_challenge[128];
    int attestation_challenge_len;
    root_of_trust_t root_of_trust;
    authorization_list_t software_enforced;
    authorization_list_t tee_enforced;
    int has_attestation_extension;
} tee_info_t;

// 解析 TEE certificate
int parse_tee_certificate(const unsigned char* cert_data, int cert_len, tee_info_t* tee_info);

// 取得 security level
int get_tee_security_level(const tee_info_t* tee_info);

// 取得 RootOfTrust
int get_tee_root_of_trust(const tee_info_t* tee_info, root_of_trust_t* root_of_trust);

// 檢查 device_locked 與 verified_boot_state
int check_tee_security_status(const tee_info_t* tee_info, int* device_locked, int* verified_boot_state);

// 檢查 attestation extension 是否存在
int has_tee_attestation_extension(const tee_info_t* tee_info);

// ASN.1 helper
int parse_asn1_integer(const unsigned char* data, int len);
void bytes_to_hex(const unsigned char* data, int len, char* hex_str);
int compare_oid(const unsigned char* data, int len, const char* oid);

#ifdef __cplusplus
}
#endif

#endif  // TAMPERPROBE_TEE_CERT_PARSER_H
