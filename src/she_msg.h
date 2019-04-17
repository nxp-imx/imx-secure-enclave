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

#ifndef SHE_MSG_H
#define SHE_MSG_H

#include "she_platform.h"

#define MESSAGING_TAG_COMMAND                   0x17u
#define MESSAGING_TAG_RESPONSE                  0xe1u
#define MESSAGING_VERSION_6                     0x06u

#define SAB_SESSION_OPEN_REQ                    0x10u
#define SAB_SESSION_CLOSE_REQ                   0x11u
#define SAB_SHARED_BUF_REQ                      0x12u

#define SAB_RNG_OPEN_REQ                        0x20u
#define SAB_RNG_CLOSE_REQ                       0x21u
#define SAB_RNG_GET_RANDOM                      0x22u
#define SAB_RNG_EXTEND_SEED                     0x23u

#define SAB_KEY_STORE_OPEN_REQ                  0x30u
#define SAB_KEY_STORE_CLOSE_REQ                 0x31u

#define SAB_KEY_MANAGEMENT_OPEN_REQ             0x40u
#define SAB_KEY_MANAGEMENT_CLOSE_REQ            0x41u
#define SAB_KEY_GENERATE_REQ                    0x42u
#define SAB_KEY_UPDATE_REQ                      0x43u
#define SAB_MANAGE_KEY_REQ                      0x44u

#define SAB_MAC_OPEN_REQ                        0x50u
#define SAB_MAC_CLOSE_REQ                       0x51u
#define SAB_MAC_ONE_GO_REQ                      0x52u
#define SAB_FAST_MAC_REQ                        0x53u

#define SAB_CIPHER_OPEN_REQ                     0x60u
#define SAB_CIPHER_CLOSE_REQ                    0x61u
#define SAB_CIPHER_ONE_GO_REQ                   0x62u

#define SAB_SHE_UTILS_OPEN                      0xF0u
#define SAB_SHE_UTILS_CLOSE                     0xF1u
#define SAB_SHE_KEY_UPDATE                      0xF2u
#define SAB_SHE_PLAIN_KEY_UPDATE                0xF3u
#define SAB_SHE_PLAIN_KEY_EXPORT                0xF4u
#define SAB_SHE_GET_ID                          0xF5u
#define SAB_SHE_GET_STATUS                      0xF6u


#define AHAB_SHE_CMD_GENERATE_MAC               0x31u
#define AHAB_SHE_CMD_VERIFY_MAC                 0x32u
#define AHAB_SHE_CMD_STORAGE_EXPORT_INIT        0x33u
#define AHAB_SHE_CMD_LOAD_KEY                   0x34u
#define AHAB_SHE_CMD_STORAGE_EXPORT_REQ         0x35u
#define AHAB_SHE_CMD_STORAGE_IMPORT_REQ         0x36u
#define AHAB_SHE_CMD_GET_STATUS_REQ             0x3Bu
#define AHAB_SHE_CMD_GET_ID_REQ                 0x3Cu
#define AHAB_SHE_CMD_LOAD_PLAIN_KEY_REQ         0x3Du

#define GET_STATUS_CODE(rsp_code)               ((uint8_t)((rsp_code) & 0xFFu))
#define GET_RATING_CODE(rsp_code)               ((uint8_t)((rsp_code) >> 8))

/* Status code definition */
#define SAB_SUCCESS_STATUS                      0x00u
#define SAB_FAILURE_STATUS                      0x29u

/* Rating code definition */
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

/* Fill a command message header with a given command ID and length in bytes. */
static inline void she_fill_cmd_msg_hdr(struct she_mu_hdr *hdr, uint8_t cmd, uint32_t len)
{
    hdr->tag = MESSAGING_TAG_COMMAND;
    hdr->command = cmd;
    hdr->size = (uint8_t)(len / sizeof(uint32_t));
    hdr->ver = MESSAGING_VERSION_6;
};

/* Fill a response message header with a given command ID and length in bytes. */
static inline void she_fill_rsp_msg_hdr(struct she_mu_hdr *hdr, uint8_t cmd, uint32_t len)
{
    hdr->tag = MESSAGING_TAG_RESPONSE;
    hdr->command = cmd;
    hdr->size = (uint8_t)(len / sizeof(uint32_t));
    hdr->ver = MESSAGING_VERSION_6;
};

/* MAC generation */

struct she_cmd_generate_mac_msg {
    struct she_mu_hdr hdr;
    uint16_t key_id;
    uint16_t data_length;
    uint16_t data_offset;
    uint16_t mac_offset;
};

struct she_cmd_generate_mac_rsp {
    struct she_mu_hdr header;
    uint32_t rsp_code;
};

/* MAC verify */

struct she_cmd_verify_mac_msg{
    struct she_mu_hdr hdr;
    uint16_t key_id;
    uint16_t data_length;
    uint16_t data_offset;
    uint16_t mac_offset;
    uint16_t mac_length;
    uint16_t pad;
};

struct she_cmd_verify_mac_rsp{
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t verification_status;
};

/* Load key */

struct she_cmd_load_key_msg {
    struct she_mu_hdr hdr;
};

struct she_cmd_load_key_rsp  {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

/* Load Plain key */

struct she_cmd_load_plain_key_msg {
    struct she_mu_hdr hdr;
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
    uint32_t sesssion_handle;
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

struct she_cmd_get_status_msg {
       struct she_mu_hdr hdr;
};

struct she_cmd_get_status_rsp {
       struct she_mu_hdr hdr;
       uint32_t rsp_code;
       uint8_t sreg;
       uint8_t pad[3];
};

struct she_cmd_get_id_msg {
    struct she_mu_hdr hdr;
    uint8_t challenge[16];
    uint32_t outputs_address_ext;
    uint32_t mac_addr;
    uint32_t crc;
};

struct she_cmd_get_id_rsp {
       struct she_mu_hdr hdr;
       uint32_t rsp_code;
       uint8_t id[15];
       uint8_t sreg;
       uint32_t crc;
};

/* SHE storage */

struct she_cmd_blob_export_init_msg{
    struct she_mu_hdr hdr;
    uint32_t blob_size;
};

struct she_cmd_blob_export_init_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
    uint32_t load_address_ext;
    uint32_t load_address;
};

struct she_cmd_blob_export_msg {
    struct she_mu_hdr hdr;
};

struct she_cmd_blob_export_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct she_cmd_blob_import_msg {
    struct she_mu_hdr hdr;
    uint32_t load_address_ext;
    uint32_t load_address;
    uint32_t blob_size;
};

struct she_cmd_blob_import_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
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
    uint32_t sesssion_handle;
};

struct sab_cmd_session_close_msg {
    struct she_mu_hdr hdr;
    uint32_t sesssion_handle;
};

struct sab_cmd_session_close_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
};

struct sab_cmd_key_store_open_msg{
    struct she_mu_hdr hdr;
    uint32_t sesssion_handle;
    uint32_t key_store_id;
    uint32_t password;
    uint32_t input_address_ext;
    uint32_t output_address_ext;
    uint8_t flags;
    uint8_t rsv;
    uint16_t rsv_1;
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
    uint32_t data_length;
    uint32_t crc;
} ;

struct sab_cmd_cipher_one_go_rsp {
    struct she_mu_hdr hdr;
    uint32_t rsp_code;
} ;
#endif
