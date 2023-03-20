/*
 * Copyright 2019-2023 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */


#ifndef SAB_MSG_H
#define SAB_MSG_H

#include <stdint.h>
#include <plat_sab_msg_def.h>

#define MESSAGING_TAG_COMMAND                   0x17u
#define MESSAGING_TAG_RESPONSE                  0xe1u
#define MESSAGING_VERSION_6                     0x06u
#define MESSAGING_VERSION_7                     0x07u

#define V2X_SV0_API_VER                         0x02u
#define V2X_SV0_REQ_TAG                         0x18u
#define V2X_SV0_IND_TAG                         0xe2u

#define V2X_SV1_API_VER                         0x02u
#define V2X_SV1_REQ_TAG                         0x19u
#define V2X_SV1_IND_TAG                         0xe3u

#define V2X_SHE_API_VER                         0x02u
#define V2X_SHE_REQ_TAG                         0x1au
#define V2X_SHE_IND_TAG                         0xe4u

#define V2X_SG0_API_VER                         0x02u
#define V2X_SG0_REQ_TAG                         0x1du
#define V2X_SG0_IND_TAG                         0xe7u

#define V2X_SG1_API_VER                         0x02u
#define V2X_SG1_REQ_TAG                         0x1eu
#define V2X_SG1_IND_TAG                         0xe8u

#define SAB_SESSION_OPEN_REQ                    0x10u
#define SAB_SESSION_CLOSE_REQ                   0x11u
#define SAB_SHARED_BUF_REQ                      0x12u
#define SAB_PUB_KEY_RECONSTRUCTION_REQ          0x13u
#define SAB_PUB_KEY_DECOMPRESSION_REQ           0x14u
#define SAB_ECIES_ENC_REQ                       0x15u
#define SAB_GET_INFO_REQ                        0x16u

#define SAB_RNG_OPEN_REQ                        0x20u
#define SAB_RNG_CLOSE_REQ                       0x21u

/* For debug s400, dump messsage
 * cmd id = 0x21, but version is 0x6
 */
#define ROM_DEBUG_DUMP_REQ                      0x21u
#define ROM_DEBUG_DUMP_MSG_SZ                   0x01u

#define SAB_RNG_GET_RANDOM                      0x22u
#define SAB_RNG_EXTEND_SEED                     0x23u

#define SAB_KEY_STORE_OPEN_REQ                  0x30u
#define SAB_KEY_STORE_CLOSE_REQ                 0x31u
#define SAB_PUB_KEY_RECOVERY_REQ                0x32u

#define SAB_KEY_MANAGEMENT_OPEN_REQ             0x40u
#define SAB_KEY_MANAGEMENT_CLOSE_REQ            0x41u
#define SAB_KEY_GENERATE_REQ                    0x42u
#define SAB_MANAGE_KEY_REQ                      0x43u
#define SAB_BUT_KEY_EXP_REQ                     0x44u
#define SAB_MANAGE_KEY_GROUP_REQ                0x45u
#define SAB_ROOT_KEK_EXPORT_REQ                 0x46u
#define SAB_KEY_EXCHANGE_REQ                    0x47u
#define SAB_TLS_FINISH_REQ                      0x48u
#define SAB_KEY_GENERATE_EXT_REQ                0x49u
#define SAB_MANAGE_KEY_EXT_REQ                  0x4au
#define SAB_IMPORT_KEY_EXT_REQ                  0x4au
#define SAB_ST_BUT_KEY_EXP_REQ                  0x4bu
#define SAB_GET_KEY_ATTR_REQ                    0x4Cu
#define SAB_DELETE_KEY_REQ                      0x4Eu
#define SAB_IMPORT_KEY_REQ                      0x4Fu

#define SAB_MAC_OPEN_REQ                        0x50u
#define SAB_MAC_CLOSE_REQ                       0x51u
#define SAB_MAC_ONE_GO_REQ                      0x52u

#define SAB_CIPHER_OPEN_REQ                     0x60u
#define SAB_CIPHER_CLOSE_REQ                    0x61u
#define SAB_CIPHER_ONE_GO_REQ                   0x62u
#define SAB_CIPHER_ECIES_DECRYPT_REQ            0x63u
#define SAB_AUTH_ENC_REQ                        0x64u

#define SAB_SIGNATURE_GENERATION_OPEN_REQ       0x70u
#define SAB_SIGNATURE_GENERATION_CLOSE_REQ      0x71u
#define SAB_SIGNATURE_GENERATE_REQ              0x72u
#define SAB_SIGNATURE_PREPARE_REQ               0x73u

#define SAB_SIGNATURE_VERIFICATION_OPEN_REQ     0x80u
#define SAB_SIGNATURE_VERIFICATION_CLOSE_REQ    0x81u
#define SAB_SIGNATURE_VERIFY_REQ                0x82u
#define SAB_IMPORT_PUB_KEY                      0x83u

#define SAB_HASH_OPEN_REQ                       0x90u
#define SAB_HASH_CLOSE_REQ                      0x91u
#ifndef SAB_HASH_ONE_GO_REQ
#define SAB_HASH_ONE_GO_REQ                     0xCCu
#endif

#define SAB_DATA_STORAGE_OPEN_REQ               0xA0u
#define SAB_DATA_STORAGE_CLOSE_REQ              0xA1u
#define SAB_DATA_STORAGE_REQ                    0xA2u

#define SAB_SM2_GET_Z_REQ                       0xB0U
#define SAB_SM2_ECES_ENC_REQ                    0xB1U
#define SAB_SM2_ECES_DEC_OPEN_REQ               0xB2U
#define SAB_SM2_ECES_DEC_CLOSE_REQ              0xB3U
#define SAB_SM2_ECES_DEC_REQ                    0xB4U

#define SAB_KEY_GENERIC_CRYPTO_SRV_OPEN_REQ     0xC0U
#define SAB_KEY_GENERIC_CRYPTO_SRV_CLOSE_REQ    0xC1U
#define SAB_KEY_GENERIC_CRYPTO_SRV_REQ          0xC2U

#define ROM_DEV_FWD_LC_UPDATE                   0x95
#define ROM_DEV_RET_LC_UPDATE                   0xA0
#define ROM_DEV_GETINFO_REQ                     0xDA
#define ROM_DEV_ATTEST_REQ                      0xDB

/* FW: Maximum number of words without crc in a command */
#define SAB_STORAGE_NB_WORDS_MAX_WO_CRC         4u

#define SAB_STORAGE_OPEN_REQ                    0xE0u
#define SAB_STORAGE_CLOSE_REQ                   0xE1u
#define SAB_STORAGE_MASTER_IMPORT_REQ           0xE2u
#define SAB_STORAGE_MASTER_EXPORT_REQ           0xE3u
#define SAB_STORAGE_EXPORT_FINISH_REQ           0xE4u
#define SAB_STORAGE_CHUNK_EXPORT_REQ            0xE5u
#define SAB_STORAGE_CHUNK_GET_REQ               0xE6u
#define SAB_STORAGE_CHUNK_GET_DONE_REQ          0xE7u
#define SAB_RCVMSG_START_ID                     SAB_STORAGE_OPEN_REQ
#define SAB_STORAGE_NVM_LAST_CMD                (SAB_STORAGE_CHUNK_GET_DONE_REQ + 1)

#define SAB_RCVMSG_MAX_ID                       (SAB_STORAGE_CHUNK_GET_DONE_REQ \
							- SAB_RCVMSG_START_ID)

#define SAB_SHE_UTILS_OPEN                      0xF0u
#define SAB_SHE_UTILS_CLOSE                     0xF1u
#define SAB_SHE_KEY_UPDATE                      0xF2u
#define SAB_SHE_PLAIN_KEY_UPDATE                0xF3u
#define SAB_SHE_PLAIN_KEY_EXPORT                0xF4u
#define SAB_SHE_GET_ID                          0xF5u
#define SAB_SHE_GET_STATUS                      0xF6u
#define SAB_FAST_MAC_REQ                        0xF7u
#define SAB_SHE_KEY_UPDATE_EXT                  0xF8u

#define SAB_MSG_MAX_ID				0xFFu

#define GET_STATUS_CODE(rsp_code)               ((uint8_t)((rsp_code) & 0xFFu))
#define GET_RATING_CODE(rsp_code)               ((uint8_t)((rsp_code) >> 8))

/* Status code definition */
#define SAB_FAILURE_STATUS                      0x29u
#define ROM_SUCCESS_STATUS                      0xD6u
#define SAB_SUCCESS_STATUS                      0xD6u
#define SAB_CRC_FAILURE_STATUS                  0xB929u
#define SAB_INVALID_MSG_STATUS                  0xF429u

#define SAB_STATUS_SUCCESS(msg_type)            ((msg_type == ROM_MSG) ? \
							ROM_SUCCESS_STATUS \
							: SAB_SUCCESS_STATUS)

/* 4 word is must for adding CRC. */
#define NB_BYTES_CRC_MANDATE                    (0x10u)

/* Rating code definition */
#define SAB_NO_MESSAGE_RATING                   (0x00u)
#define SAB_INVALID_MESSAGE_RATING              (0x01u)
#define SAB_INVALID_ADDRESS_RATING              (0x02u)
#define SAB_UNKNOWN_ID_RATING                   (0x03u)
#define SAB_INVALID_PARAM_RATING                (0x04u)
#define SAB_NVM_ERROR_RATING                    (0x05u)
#define SAB_OUT_OF_MEMORY_RATING                (0x06u)
#define SAB_UNKNOWN_HANDLE_RATING               (0x07u)
#define SAB_UNKNOWN_KEY_STORE_RATING            (0x08u)
#define SAB_KEY_STORE_AUTH_RATING               (0x09u)
#define SAB_KEY_STORAGE_ERROR_RATING            (0x0Au)
#define SAB_ID_CONFLICT_RATING                  (0x0Bu)
#define SAB_RNG_NOT_STARTED_RATING              (0x0Cu)
#define SAB_CMD_NOT_SUPPORTED_RATING            (0x0Du)
#define SAB_INVALID_LIFECYCLE_RATING            (0x0Eu)
#define SAB_KEY_STORE_CONFLICT_RATING           (0x0Fu)
#define SAB_KEY_STORE_COUNTER_RATING            (0x10u)
#define SAB_FEATURE_NOT_SUPPORTED_RATING        (0x11u)
#define SAB_SELF_TEST_FAILURE_RATING            (0x12u)
#define SAB_NOT_READY_RATING                    (0x13u)
#define SAB_FEATURE_DISABLED_RATING             (0x14u)
#define SAB_SIGNED_MSG_INVALID_RATING           (0x18u)
#define SAB_OUT_OF_MEM_TO_STORE_KEY_IN_KEYGRP   (0x19u)
#define SAB_NOT_POSSIBLE_RETRIEVE_CHUNK         (0x1Au)
#define SAB_KEY_NOT_SUPPORTED_RATING            (0x1Bu)
#define SAB_TRYING_TO_DEL_PERM_KEY              (0x1Cu)
#define SAB_OUT_LEN_TOO_SHORT_RATING            (0x1Du)
#define SAB_CRC_CHECK_FAIL_RATING               (0xB9u)

/* SHE specific rating */
#define SAB_SHE_SEQUENCE_ERROR_RATING           (0xD1u)     /**< Invalid sequence of commands. */
#define SAB_SHE_KEY_NOT_AVAILABLE_RATING        (0xD2u)     /**< Key is locked. */
#define SAB_SHE_KEY_INVALID_RATING              (0xD3u)     /**< Key not allowed for the given operation. */
#define SAB_SHE_KEY_EMPTY_RATING                (0xD4u)     /**< Key has not beed initialized yet. */
#define SAB_SHE_NO_SECURE_BOOT_RATING           (0xD5u)     /**< Conditions for a secure boot process are not met. */
#define SAB_SHE_KEY_WRITE_PROTECTED_RATING      (0xD6u)     /**< Memory slot for this key has been write-protected. */
#define SAB_SHE_KEY_UPDATE_ERROR_RATING         (0xD7u)     /**< Key update did not succeed due to errors in verification of the messages. */
#define SAB_SHE_RNG_SEED_RATING                 (0xD8u)     /*< The seed has not been initialized. */
#define SAB_SHE_NO_DEBUGGING_RATING             (0xD9u)     /**< Internal debugging is not possible. */
#define SAB_SHE_BUSY_RATING                     (0xDAu)     /**< A function of SHE is called while another function is still processing. */
#define SAB_SHE_MEMORY_FAILURE_RATING           (0xDBu)     /**< Memory error (e.g. flipped bits) */
#define SAB_SHE_GENERAL_ERROR_RATING            (0xDCu)     /**< Error not covered by other codes occured. */

#define SAB_READ_FAILURE_RATING                 (0xFEu)
#define SAB_FATAL_FAILURE_RATING                (0xFFu)

#define SAB_MSG_CRC_BIT		(1 << 31)
#define SAB_RSP_CRC_BIT		(1 << 30)

struct sab_mu_hdr {
    uint8_t ver;
    uint8_t size;
    uint8_t command;
    uint8_t tag;
};

/* MAC generation / verify */

struct sab_she_fast_mac_msg {
    struct sab_mu_hdr hdr;
    uint32_t she_utils_handle;
    uint16_t key_id;
    uint16_t data_length;
    uint16_t data_offset;
    uint8_t mac_length;
    uint8_t flags;
};
#define SAB_SHE_FAST_MAC_FLAGS_VERIFICATION    (1u)
#define SAB_SHE_FAST_MAC_FLAGS_VERIF_BIT_LEN   (2u)

struct sab_she_fast_mac_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t verification_status;
};
#define SAB_SHE_FAST_MAC_VERIFICATION_STATUS_OK  (0x5A3CC3A5u)
#define SAB_SHE_FAST_MAC_VERIFICATION_STATUS_KO  (0u)

/* Update key */

struct sab_she_key_update_msg {
    struct sab_mu_hdr hdr;
    uint32_t utils_handle;
    uint32_t key_id;
    uint32_t m1[4];
    uint32_t m2[8];
    uint32_t m3[4];
    uint32_t crc;
};

struct sab_she_key_update_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t m4[8];
    uint32_t m5[4];
    uint32_t crc;
};

/* Update key extension */

struct sab_she_key_update_ext_msg {
    struct sab_mu_hdr hdr;
    uint32_t utils_handle;
    uint32_t key_id;
    uint32_t m1[4];
    uint32_t m2[8];
    uint32_t m3[4];
    uint8_t  flags;
    uint8_t  pad[3];
    uint32_t crc;
};

struct sab_she_key_update_ext_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t m4[8];
    uint32_t m5[4];
    uint32_t crc;
};

/* SHE export plain key (Ram key) */
struct sab_she_plain_key_export_msg {
    struct sab_mu_hdr hdr;
    uint32_t utils_handle;
} ;

struct sab_she_plain_key_export_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t m1[4];
    uint32_t m2[8];
    uint32_t m3[4];
    uint32_t m4[8];
    uint32_t m5[4];
    uint32_t crc;
} ;

/* Load Plain key */

struct she_cmd_load_plain_key_msg {
    struct sab_mu_hdr hdr;
    uint32_t she_utils_handle;
    uint8_t key[16];
    uint32_t crc;
};

struct she_cmd_load_plain_key_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};

/* SHE inititalization */

struct sab_cmd_shared_buffer_msg {
    struct sab_mu_hdr hdr;
    uint32_t session_handle;
};

struct sab_cmd_shared_buffer_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
    uint16_t shared_buf_offset;
    uint16_t shared_buf_size;
};


/* SHE random generation */

struct sab_cmd_extend_seed_msg {
    struct sab_mu_hdr hdr;
    uint32_t rng_handle;
    uint32_t entropy[4];
    uint32_t crc;
};

struct sab_cmd_extend_seed_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};

/* SHE Storage */
struct she_cmd_get_status_msg {
       struct sab_mu_hdr hdr;
       uint32_t she_utils_handle;
};

struct she_cmd_get_status_rsp {
       struct sab_mu_hdr hdr;
       uint32_t rsp_code;
       uint8_t sreg;
       uint8_t pad[3];
};

struct she_cmd_get_id_msg {
    struct sab_mu_hdr hdr;
    uint32_t she_utils_handle;
    uint8_t challenge[16];
    uint32_t crc;
};

struct she_cmd_get_id_rsp {
       struct sab_mu_hdr hdr;
       uint32_t rsp_code;
       uint8_t id[15];
       uint8_t sreg;
       uint8_t mac[16];
       uint32_t crc;
};

struct sab_cmd_key_store_open_msg{
    struct sab_mu_hdr hdr;
    uint32_t session_handle;
    uint32_t key_store_id;
    uint32_t password;
    uint16_t max_updates;
    uint8_t flags;
#ifndef PSA_COMPLIANT
    uint8_t min_mac_length;
#else
    uint8_t rsv;
#endif
    uint32_t crc;
} ;

struct sab_cmd_key_store_open_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t key_store_handle;
} ;

struct sab_cmd_key_store_close_msg{
    struct sab_mu_hdr hdr;
    uint32_t key_store_handle;
} ;

struct sab_cmd_key_store_close_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
} ;

struct sab_cmd_key_management_open_msg{
    struct sab_mu_hdr hdr;
    uint32_t key_store_handle;
    uint32_t input_address_ext;
    uint32_t output_address_ext;
    uint8_t flags;
    uint8_t rsv[3];
    uint32_t crc;
};

struct sab_cmd_key_management_open_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t key_management_handle;
};


struct sab_cmd_manage_key_group_msg {
    struct sab_mu_hdr hdr;
    uint32_t key_management_handle;
    uint16_t key_group;
    uint8_t flags;
    uint8_t rsv;
};

struct sab_cmd_manage_key_group_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};


struct sab_cmd_butterfly_key_exp_msg {
    struct sab_mu_hdr hdr;
    uint32_t key_management_handle;
    uint32_t key_identifier;
    uint32_t expansion_function_value_addr;
    uint32_t hash_value_addr;
    uint32_t pr_reconstruction_value_addr;
    uint8_t expansion_function_value_size;
    uint8_t hash_value_size;
    uint8_t pr_reconstruction_value_size;
    uint8_t flags;
    uint32_t dest_key_identifier;
    uint32_t output_address;
    uint16_t output_size;
    uint8_t key_type;
    uint8_t rsv;
    uint16_t key_group;
    uint16_t key_info;
    uint32_t crc;
};

struct sab_cmd_butterfly_key_exp_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t dest_key_identifier;
};


struct sab_cmd_key_management_close_msg{
    struct sab_mu_hdr hdr;
    uint32_t key_management_handle;
};

struct sab_cmd_key_management_close_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};

#define AHAB_CIPHER_ONE_GO_ALGO_ECB (0x00u)
#define AHAB_CIPHER_ONE_GO_ALGO_CBC (0x01u)
#define AHAB_CIPHER_ONE_GO_FLAGS_ENCRYPT (0x01u)
#define AHAB_CIPHER_ONE_GO_FLAGS_DECRYPT (0x00u)

#define SAB_AUTH_ENC_ALGO_GCM 0x00
#define SAB_AUTH_ENC_FLAGS_ENCRYPT (0x01u)
#define SAB_AUTH_ENC_FLAGS_DECRYPT (0x00u)

struct sab_cmd_ecies_decrypt_msg {
    struct sab_mu_hdr hdr;
    uint32_t cipher_handle;
    uint32_t key_id;
    uint32_t input_address;
    uint32_t p1_addr;
    uint32_t p2_addr;
    uint32_t output_address;
    uint32_t input_size;
    uint32_t output_size;
    uint16_t p1_size;
    uint16_t p2_size;
    uint16_t mac_size;
    uint8_t key_type;
    uint8_t flags;
    uint32_t crc;
};

struct sab_cmd_ecies_decrypt_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_she_utils_open_msg{
    struct sab_mu_hdr hdr;
    uint32_t key_store_handle;
    uint32_t input_address_ext;
    uint32_t output_address_ext;
} ;

struct sab_cmd_she_utils_open_rsp{
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t utils_handle;
} ;

struct sab_cmd_she_utils_close_msg {
    struct sab_mu_hdr hdr;
    uint32_t utils_handle;
} ;

struct sab_cmd_she_utils_close_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
} ;

struct sab_import_pub_key_msg {
    struct sab_mu_hdr hdr;
    uint32_t sig_ver_hdl;
    uint32_t key_addr;
    uint16_t key_size;
    uint8_t key_type;
    uint8_t flags;
};

struct sab_import_pub_key_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t key_ref;
};


struct sab_public_key_reconstruct_msg {
    struct sab_mu_hdr hdr;
    uint32_t sesssion_handle;
    uint32_t pu_address_ext;
    uint32_t pu_address;
    uint32_t hash_address_ext;
    uint32_t hash_address;
    uint32_t ca_key_address_ext;
    uint32_t ca_key_address;
    uint32_t out_key_address_ext;
    uint32_t out_key_address;
    uint16_t pu_size;
    uint16_t hash_size;
    uint16_t ca_key_size;
    uint16_t out_key_size;
    uint8_t key_type;
    uint8_t flags;
    uint16_t rsv;
    uint32_t crc;
};

struct sab_public_key_reconstruct_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_public_key_decompression_msg {
    struct sab_mu_hdr hdr;
    uint32_t sesssion_handle;
    uint32_t input_address_ext;
    uint32_t input_address;
    uint32_t output_address_ext;
    uint32_t output_address;
    uint16_t input_size;
    uint16_t out_size;
    uint8_t key_type;
    uint8_t flags;
    uint16_t rsv;
    uint32_t crc;
};

struct sab_public_key_decompression_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_ecies_encrypt_msg {
    struct sab_mu_hdr hdr;
    uint32_t sesssion_handle;
    uint32_t input_addr_ext;
    uint32_t input_addr;
    uint32_t key_addr_ext;
    uint32_t key_addr;
    uint32_t p1_addr_ext;
    uint32_t p1_addr;
    uint32_t p2_addr_ext;
    uint32_t p2_addr;
    uint32_t output_addr_ext;
    uint32_t output_addr;
    uint32_t input_size;
    uint16_t p1_size;
    uint16_t p2_size;
    uint16_t key_size;
    uint16_t mac_size;
    uint32_t output_size;
    uint8_t key_type;
    uint8_t flags;
    uint16_t reserved;
    uint32_t crc;
};

struct sab_cmd_ecies_encrypt_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_root_kek_export_msg {
    struct sab_mu_hdr hdr;
    uint32_t session_handle;
    uint32_t root_kek_address_ext;
    uint32_t root_kek_address;
    uint8_t root_kek_size;
    uint8_t flags;
    uint16_t reserved;
    uint32_t crc;
};

struct sab_root_kek_export_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};

/* SM2 Get Z */
struct sab_cmd_sm2_get_z_msg {
    struct sab_mu_hdr hdr;
    uint32_t session_handle;
    uint32_t input_address_ext;
    uint32_t public_key_address;
    uint32_t id_address;
    uint32_t output_address_ext;
    uint32_t z_value_address;
    uint16_t public_key_size;
    uint8_t id_size;
    uint8_t z_size;
    uint8_t key_type;
    uint8_t flags;
    uint16_t reserved;
    uint32_t crc;
};

struct sab_cmd_sm2_get_z_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};

/* SM2 ECES ENC */
struct sab_cmd_sm2_eces_enc_msg {
    struct sab_mu_hdr hdr;
    uint32_t session_handle;
    uint32_t input_addr_ext;
    uint32_t input_addr;
    uint32_t key_addr_ext;
    uint32_t key_addr;
    uint32_t output_addr_ext;
    uint32_t output_addr;
    uint32_t input_size;
    uint32_t output_size;
    uint16_t key_size;
    uint8_t key_type;
    uint8_t flags;
    uint32_t crc;
};

struct sab_cmd_sm2_eces_enc_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_sm2_eces_dec_open_msg {
    struct sab_mu_hdr hdr;
    uint32_t key_store_handle;
    uint32_t input_address_ext;
    uint32_t output_address_ext;
    uint8_t flags;
    uint8_t rsv[3];
    uint32_t crc;
};

struct sab_cmd_sm2_eces_dec_open_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t sm2_eces_handle;
};

struct sab_cmd_sm2_eces_dec_close_msg {
    struct sab_mu_hdr hdr;
    uint32_t sm2_eces_handle;
};

struct sab_cmd_sm2_eces_dec_close_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_sm2_eces_dec_msg{
    struct sab_mu_hdr hdr;
    uint32_t sm2_eces_handle;
    uint32_t key_id;
    uint32_t input_address;
    uint32_t output_address;
    uint32_t input_size;
    uint32_t output_size;
    uint8_t key_type;
    uint8_t  flags;
    uint16_t rsv;
    uint32_t crc;
} ;

struct sab_cmd_sm2_eces_dec_rsp{
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
} ;

struct sab_cmd_key_exchange_msg {
    struct sab_mu_hdr hdr;
    uint32_t key_management_handle;
    uint32_t key_identifier;
    uint32_t shared_key_identifier_array;
    uint32_t ke_input_addr;
    uint32_t ke_output_addr;
    uint32_t kdf_input_data;
    uint32_t kdf_output_data;
    uint16_t shared_key_group;
    uint16_t shared_key_info;
    uint8_t shared_key_type;
    uint8_t initiator_public_data_type;
    uint8_t key_exchange_algorithm;
    uint8_t kdf_algorithm;
    uint16_t ke_input_data_size;
    uint16_t ke_output_data_size;
    uint8_t shared_key_identifier_array_size;
    uint8_t kdf_input_size;
    uint8_t kdf_output_size;
    uint8_t flags;
    uint32_t crc;
};

struct sab_cmd_key_exchange_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_tls_finish_msg{
    struct sab_mu_hdr hdr;
    uint32_t        key_management_handle;
    uint32_t        key_identifier;
    uint32_t        handshake_hash_input_addr;
    uint32_t        verify_data_output_addr;
    uint16_t        handshake_hash_input_size;
    uint16_t        verify_data_output_size;
    uint8_t         flags;
    uint8_t         hash_algorithm;
    uint16_t        reserved;
    uint32_t        crc;
};

struct sab_cmd_tls_finish_rsp{
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_st_butterfly_key_exp_msg {
    struct sab_mu_hdr hdr;
    uint32_t key_management_handle;
    uint32_t key_identifier;
    uint32_t exp_fct_key_identifier;
    uint32_t exp_fct_input_address;
    uint32_t hash_value_address;
    uint32_t pr_reconst_value_address;
    uint8_t  exp_fct_input_size;
    uint8_t  hash_value_size;
    uint8_t  pr_reconst_value_size;
    uint8_t  flags;
    uint32_t dest_key_identifier;
    uint32_t output_address;
    uint16_t output_size;
    uint8_t  key_type;
    uint8_t  exp_fct_algorithm;
    uint16_t key_group;
    uint16_t key_info;
    uint32_t crc;
};

struct sab_cmd_st_butterfly_key_exp_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t dest_key_identifier;
};

struct sab_key_generic_crypto_srv_open_msg {
    struct sab_mu_hdr header;
    uint32_t session_handle;
    uint32_t input_address_ext;
    uint32_t output_address_ext;
    uint8_t flags;
    uint8_t rsv[3];
    uint32_t crc;
};

struct sab_key_generic_crypto_srv_open_rsp {
    struct sab_mu_hdr header;
    uint32_t rsp_code;
    uint32_t key_generic_crypto_srv_handle;
};

struct sab_key_generic_crypto_srv_close_msg {
    struct sab_mu_hdr header;
    uint32_t key_generic_crypto_srv_handle;
};

struct sab_key_generic_crypto_srv_close_rsp {
    struct sab_mu_hdr header;
    uint32_t rsp_code;
};

struct sab_key_generic_crypto_srv_msg {
    struct sab_mu_hdr header;
    uint32_t key_generic_crypto_srv_handle;
    uint32_t key_address;
    uint32_t iv_address;
    uint16_t iv_size;
    uint8_t key_size;
    uint8_t crypto_algo;
    uint32_t aad_address;
    uint16_t aad_size;
    uint8_t tag_size;
    uint8_t flags;
    uint32_t input_address;
    uint32_t output_address;
    uint32_t input_length;
    uint32_t output_length;
    uint32_t rsv;
    uint32_t crc;
};

struct sab_key_generic_crypto_srv_rsp {
    struct sab_mu_hdr header;
    uint32_t rsp_code;
};

#endif
