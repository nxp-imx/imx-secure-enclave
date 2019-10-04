/*
 * Copyright 2019 NXP
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

#include "seco_os_abs.h"


#define MESSAGING_TAG_COMMAND                   0x17u
#define MESSAGING_TAG_RESPONSE                  0xe1u
#define MESSAGING_VERSION_6                     0x06u

#define SAB_SESSION_OPEN_REQ                    0x10u
#define SAB_SESSION_CLOSE_REQ                   0x11u
#define SAB_SHARED_BUF_REQ                      0x12u
#define SAB_PUB_KEY_RECONSTRUCTION_REQ          0x13u
#define SAB_PUB_KEY_DECOMPRESSION_REQ           0x14u
#define SAB_ECIES_ENC_REQ                       0x15u
#define SAB_GET_INFO_REQ                        0x16u

#define SAB_RNG_OPEN_REQ                        0x20u
#define SAB_RNG_CLOSE_REQ                       0x21u
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

#define SAB_MAC_OPEN_REQ                        0x50u
#define SAB_MAC_CLOSE_REQ                       0x51u
#define SAB_MAC_ONE_GO_REQ                      0x52u

#define SAB_CIPHER_OPEN_REQ                     0x60u
#define SAB_CIPHER_CLOSE_REQ                    0x61u
#define SAB_CIPHER_ONE_GO_REQ                   0x62u
#define SAB_CIPHER_ECIES_DECRYPT_REQ            0x63u

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
#define SAB_HASH_ONE_GO_REQ                     0x92u

#define SAB_STORAGE_OPEN_REQ                    0xE0u
#define SAB_STORAGE_CLOSE_REQ                   0xE1u
#define SAB_STORAGE_MASTER_IMPORT_REQ           0xE2u
#define SAB_STORAGE_MASTER_EXPORT_REQ           0xE3u
#define SAB_STORAGE_EXPORT_FINISH_REQ           0xE4u
#define SAB_STORAGE_CHUNK_EXPORT_REQ            0xE5u
#define SAB_STORAGE_CHUNK_GET_REQ               0xE6u
#define SAB_STORAGE_CHUNK_GET_DONE_REQ          0xE7u

#define SAB_SHE_UTILS_OPEN                      0xF0u
#define SAB_SHE_UTILS_CLOSE                     0xF1u
#define SAB_SHE_KEY_UPDATE                      0xF2u
#define SAB_SHE_PLAIN_KEY_UPDATE                0xF3u
#define SAB_SHE_PLAIN_KEY_EXPORT                0xF4u
#define SAB_SHE_GET_ID                          0xF5u
#define SAB_SHE_GET_STATUS                      0xF6u
#define SAB_FAST_MAC_REQ                        0xF7u

#define GET_STATUS_CODE(rsp_code)               ((uint8_t)((rsp_code) & 0xFFu))
#define GET_RATING_CODE(rsp_code)               ((uint8_t)((rsp_code) >> 8))

/* Status code definition */
#define SAB_SUCCESS_STATUS                      0x00u
#define SAB_FAILURE_STATUS                      0x29u

/* Rating code definition */
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

struct she_mu_hdr {
    uint8_t ver;
    uint8_t size;
    uint8_t command;
    uint8_t tag;
};

/* MAC generation / verify */

struct sab_she_fast_mac_msg {
    struct she_mu_hdr hdr;
    uint32_t she_utils_handle;
    uint16_t key_id;
    uint16_t data_length;
    uint16_t data_offset;
    uint8_t mac_length;
    uint8_t flags;
};
#define SAB_SHE_FAST_MAC_FLAGS_VERIFICATION    (1u)

struct sab_she_fast_mac_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t verification_status;
};
#define SAB_SHE_FAST_MAC_VERIFICATION_STATUS_OK  (0x5A3CC3A5u)
#define SAB_SHE_FAST_MAC_VERIFICATION_STATUS_KO  (0u)

/* Update key */

struct sab_she_key_update_msg {
    struct she_mu_hdr hdr;
    uint32_t utils_handle;
    uint32_t key_id;
    uint32_t m1[4];
    uint32_t m2[8];
    uint32_t m3[4];
    uint32_t crc;
};

struct sab_she_key_update_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t m4[8];
    uint32_t m5[4];
    uint32_t crc;
};

/* SHE export plain key (Ram key) */
struct sab_she_plain_key_export_msg {
    struct she_mu_hdr hdr;
    uint32_t utils_handle;
} ;

struct sab_she_plain_key_export_rsp {
    struct she_mu_hdr hdr;
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
    struct she_mu_hdr hdr;
    uint32_t she_utils_handle;
    uint8_t key[16];
    uint32_t crc;
};

struct she_cmd_load_plain_key_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

/* SHE inititalization */

struct sab_cmd_shared_buffer_msg {
    struct she_mu_hdr hdr;
    uint32_t session_handle;
};

struct sab_cmd_shared_buffer_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint16_t shared_buf_offset;
    uint16_t shared_buf_size;
};


/* SHE random generation */
struct sab_cmd_rng_open_msg{
    struct she_mu_hdr hdr;
    uint32_t session_handle;
    uint32_t input_address_ext;
    uint32_t output_address_ext;
    uint8_t flags;
    uint8_t pad[3];
    uint32_t crc;
};

struct sab_cmd_rng_open_rsp{
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t rng_handle;
};

struct sab_cmd_rng_close_msg {
    struct she_mu_hdr hdr;
    uint32_t rng_handle;
};

struct sab_cmd_rng_close_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_extend_seed_msg {
    struct she_mu_hdr hdr;
    uint32_t rng_handle;
    uint32_t entropy[4];
    uint32_t crc;
};

struct sab_cmd_extend_seed_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_get_rnd_msg {
    struct she_mu_hdr hdr;
    uint32_t rng_handle;
    uint32_t rnd_addr;
    uint32_t rnd_size;
};

struct sab_cmd_get_rnd_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

/* SHE Storage */
struct sab_cmd_storage_open_msg{
    struct she_mu_hdr hdr;
    uint32_t session_handle;
    uint32_t input_address_ext;
    uint32_t output_address_ext;
    uint8_t flags;
    uint8_t pad[3];
    uint32_t crc;
};

struct sab_cmd_storage_open_rsp{
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t storage_handle;
};

struct sab_cmd_storage_close_msg {
    struct she_mu_hdr hdr;
    uint32_t storage_handle;
};

struct sab_cmd_storage_close_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_key_store_import_msg {
    struct she_mu_hdr hdr;
    uint32_t storage_handle;
    uint32_t key_store_address;
    uint32_t key_store_size;
};

struct sab_cmd_key_store_import_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_key_store_export_start_msg {
    struct she_mu_hdr hdr;
    uint32_t storage_handle;
    uint32_t key_store_size;
};

struct sab_cmd_key_store_export_start_rsp {
    struct she_mu_hdr hdr;
    uint32_t storage_handle;
    uint32_t rsp_code;
    uint32_t key_store_export_address;
};

struct sab_cmd_key_store_export_finish_msg {
    struct she_mu_hdr hdr;
    uint32_t storage_handle;
    uint32_t export_status;    
};
#define SAB_EXPORT_STATUS_SUCCESS (0xBA2CC2ABu)

struct sab_cmd_key_store_export_finish_rsp {
    struct she_mu_hdr hdr;
    uint32_t storage_handle;
    uint32_t rsp_code;
};

struct sab_cmd_key_store_chunk_export_msg {
    struct she_mu_hdr hdr;
    uint32_t storage_handle;
    uint32_t chunk_size;
    uint32_t blob_id;
    uint32_t blob_id_ext;
    uint32_t crc;
};

struct sab_cmd_key_store_chunk_export_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t chunk_export_address;
};

struct sab_cmd_key_store_chunk_get_msg {
    struct she_mu_hdr hdr;
    uint32_t storage_handle;
    uint32_t blob_id;
    uint32_t blob_id_ext;
};

struct sab_cmd_key_store_chunk_get_rsp {
    struct she_mu_hdr hdr;
    uint32_t chunk_size;
    uint32_t chunk_addr;
    uint32_t rsp_code;
};

#define SAB_CHUNK_GET_STATUS_SUCCEEDED 0xCA3BB3AC

struct sab_cmd_key_store_chunk_get_done_msg {
    struct she_mu_hdr hdr;
    uint32_t storage_handle;
    uint32_t get_status;
};

struct sab_cmd_key_store_chunk_get_done_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct she_cmd_get_status_msg {
       struct she_mu_hdr hdr;
       uint32_t she_utils_handle;
};

struct she_cmd_get_status_rsp {
       struct she_mu_hdr hdr;
       uint32_t rsp_code;
       uint8_t sreg;
       uint8_t pad[3];
};

struct she_cmd_get_id_msg {
    struct she_mu_hdr hdr;
    uint32_t she_utils_handle;
    uint8_t challenge[16];
    uint32_t crc;
};

struct she_cmd_get_id_rsp {
       struct she_mu_hdr hdr;
       uint32_t rsp_code;
       uint8_t id[15];
       uint8_t sreg;
       uint8_t mac[16];
       uint32_t crc;
};

struct sab_cmd_session_open_msg {
    struct she_mu_hdr hdr;
    uint8_t mu_id;
    uint8_t interrupt_idx;
    uint8_t tz;
    uint8_t did;
    uint8_t priority;
    uint8_t operating_mode;
    uint16_t pad;
};

struct sab_cmd_session_open_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t session_handle;
};

struct sab_cmd_session_close_msg {
    struct she_mu_hdr hdr;
    uint32_t session_handle;
};

struct sab_cmd_session_close_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_key_store_open_msg{
    struct she_mu_hdr hdr;
    uint32_t session_handle;
    uint32_t key_store_id;
    uint32_t password;
    uint16_t max_updates;
    uint8_t flags;
    uint8_t rsv;
    uint32_t crc;
} ;

struct sab_cmd_key_store_open_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t key_store_handle;
} ;

struct sab_cmd_key_store_close_msg{
    struct she_mu_hdr hdr;
    uint32_t key_store_handle;
} ;

struct sab_cmd_key_store_close_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
} ;

struct sab_cmd_key_management_open_msg{
    struct she_mu_hdr hdr;
    uint32_t key_store_handle;
    uint32_t input_address_ext;
    uint32_t output_address_ext;
    uint8_t flags;
    uint8_t rsv[3];
    uint32_t crc;
};

struct sab_cmd_key_management_open_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t key_management_handle;
};

struct sab_cmd_generate_key_msg {
    struct she_mu_hdr hdr;
    uint32_t key_management_handle;
    uint32_t key_identifier;
    uint16_t out_size;
    uint8_t flags;
    uint8_t key_type;
    uint16_t key_group;
    uint16_t key_info;
    uint32_t out_key_addr;
    uint32_t crc;
};

struct sab_cmd_generate_key_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t key_identifier;
};

struct sab_cmd_manage_key_msg {
    struct she_mu_hdr hdr;
    uint32_t key_management_handle;
    uint32_t key_identifier;
    uint16_t input_size;
    uint8_t flags;
    uint8_t rsv;
    uint8_t key_type;
    uint8_t rsv_1;
    uint16_t key_info;
    uint32_t input_key_addr;
    uint32_t crc;
};

struct sab_cmd_manage_key_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t key_identifier;
};

struct sab_cmd_butterfly_key_exp_msg {
    struct she_mu_hdr hdr;
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
    uint32_t crc;
};

struct sab_cmd_butterfly_key_exp_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t dest_key_identifier;
};


struct sab_cmd_key_management_close_msg{
    struct she_mu_hdr hdr;
    uint32_t key_management_handle;
};

struct sab_cmd_key_management_close_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_cipher_open_msg{
    struct she_mu_hdr hdr;
    uint32_t key_store_handle;
    uint32_t input_address_ext;
    uint32_t output_address_ext;
    uint8_t flags;
    uint8_t rsv;
    uint16_t rsv_1;
    uint32_t crc;
} ;

struct sab_cmd_cipher_open_rsp{
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t cipher_handle;
} ;

struct sab_cmd_cipher_close_msg {
    struct she_mu_hdr hdr;
    uint32_t cipher_handle;
} ;

struct sab_cmd_cipher_close_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
} ;

#define AHAB_CIPHER_ONE_GO_ALGO_ECB (0x00u)
#define AHAB_CIPHER_ONE_GO_ALGO_CBC (0x01u)
#define AHAB_CIPHER_ONE_GO_FLAGS_ENCRYPT (0x01u)
#define AHAB_CIPHER_ONE_GO_FLAGS_DECRYPT (0x00u)

struct sab_cmd_cipher_one_go_msg {
    struct she_mu_hdr hdr;
    uint32_t cipher_handle;
    uint32_t key_id;
    uint32_t iv_address;
    uint16_t iv_size;
    uint8_t  algo;
    uint8_t  flags;
    uint32_t input_address;
    uint32_t output_address;
    uint32_t input_size;
    uint32_t output_size;
    uint32_t crc;
};

struct sab_cmd_cipher_one_go_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_ecies_decrypt_msg {
    struct she_mu_hdr hdr;
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
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_she_utils_open_msg{
    struct she_mu_hdr hdr;
    uint32_t key_store_handle;
    uint32_t input_address_ext;
    uint32_t output_address_ext;
} ;

struct sab_cmd_she_utils_open_rsp{
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t utils_handle;
} ;

struct sab_cmd_she_utils_close_msg {
    struct she_mu_hdr hdr;
    uint32_t utils_handle;
} ;

struct sab_cmd_she_utils_close_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
} ;

struct sab_signature_gen_open_msg {
    struct she_mu_hdr hdr;
    uint32_t key_store_hdl;
    uint32_t input_address_ext;
    uint32_t output_address_ext;
    uint8_t flags;
    uint8_t reserved[3];
    uint32_t crc;
};

struct sab_signature_gen_open_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t sig_gen_hdl;
};

struct sab_signature_gen_close_msg {
    struct she_mu_hdr hdr;
    uint32_t sig_gen_hdl;
};

struct sab_signature_gen_close_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_signature_generate_msg {
    struct she_mu_hdr hdr;
    uint32_t sig_gen_hdl;
    uint32_t key_identifier;
    uint32_t message_addr;
    uint32_t signature_addr;
    uint32_t message_size;
    uint16_t signature_size;
    uint8_t scheme_id;
    uint8_t flags;
    uint32_t crc;
};

struct sab_signature_generate_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_prepare_signature_msg {
    struct she_mu_hdr hdr;
    uint32_t sig_gen_hdl;
    uint8_t scheme_id;
    uint8_t flags;
    uint16_t reserved;
};

struct sab_prepare_signature_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_signature_verif_open_msg {
    struct she_mu_hdr hdr;
    uint32_t session_handle;
    uint32_t input_address_ext;
    uint32_t output_address_ext;
    uint8_t flags;
    uint8_t reserved[3];
    uint32_t crc;
};

struct sab_signature_verif_open_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t sig_ver_hdl;
};

struct sab_signature_verif_close_msg {
    struct she_mu_hdr hdr;
    uint32_t sig_ver_hdl;
};

struct sab_signature_verif_close_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_signature_verify_msg {
    struct she_mu_hdr hdr;
    uint32_t sig_ver_hdl;
    uint32_t key_addr;
    uint32_t msg_addr;
    uint32_t sig_addr;
    uint16_t key_size;
    uint16_t sig_size;
    uint32_t message_size;
    uint8_t sig_scheme;
    uint8_t flags;
    uint16_t reserved;
    uint32_t crc;
};

struct sab_signature_verify_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t verification_status;
};

struct sab_import_pub_key_msg {
    struct she_mu_hdr hdr;
    uint32_t sig_ver_hdl;
    uint32_t key_addr;
    uint16_t key_size;
    uint8_t key_type;
    uint8_t flags;
};

struct sab_import_pub_key_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t key_ref;
};


struct sab_hash_open_msg {
    struct she_mu_hdr hdr;
    uint32_t session_handle;
    uint32_t input_address_ext;
    uint32_t output_address_ext;
    uint8_t flags;
    uint8_t reserved[3];
    uint32_t crc;
};

struct sab_hash_open_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t hash_hdl;
};

struct sab_hash_close_msg {
    struct she_mu_hdr hdr;
    uint32_t hash_hdl;
};

struct sab_hash_close_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_hash_one_go_msg {
    struct she_mu_hdr hdr;
    uint32_t hash_hdl;
    uint32_t input_addr;
    uint32_t output_addr;
    uint32_t input_size;
    uint32_t output_size;
    uint8_t algo;
    uint8_t flags;
    uint16_t reserved;
    uint32_t crc;
};

struct sab_hash_one_go_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_public_key_reconstruct_msg {
    struct she_mu_hdr hdr;
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
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_public_key_decompression_msg {
    struct she_mu_hdr hdr;
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
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_ecies_encrypt_msg {
    struct she_mu_hdr hdr;
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
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_get_info_msg {
    struct she_mu_hdr hdr;
    uint32_t session_handle;
};

struct sab_cmd_get_info_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t user_sab_id;
    uint32_t uid_lower;
    uint32_t uid_upper;
    uint16_t monotonic_counter;
    uint16_t lifecycle;
    uint32_t version;
    uint32_t version_ext;
    uint8_t  fips_mode;
    uint8_t  rsv[3];
    uint32_t crc;
};

struct sab_cmd_pub_key_recovery_msg {
    struct she_mu_hdr hdr;
    uint32_t key_store_handle;
    uint32_t key_identifier;
    uint32_t out_key_addr_ext;    
    uint32_t out_key_addr;
    uint16_t out_key_size;
    uint8_t key_type;
    uint8_t flags;
    uint32_t crc;
};

struct sab_cmd_pub_key_recovery_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

#endif
