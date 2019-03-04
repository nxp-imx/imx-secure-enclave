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

#include "she_platform.h"

#define MESSAGING_TAG_COMMAND					0x17
#define MESSAGING_TAG_RESPONSE					0xe1
#define MESSAGING_VERSION_2						0x02

#define AHAB_SHE_INIT							0x30
#define AHAB_SHE_CMD_GENERATE_MAC				0x31
#define AHAB_SHE_CMD_VERIFY_MAC					0x32
#define AHAB_SHE_CMD_STORAGE_EXPORT_INIT		0x33
#define AHAB_SHE_CMD_LOAD_KEY					0x34
#define AHAB_SHE_CMD_STORAGE_EXPORT_REQ			0x35
#define AHAB_SHE_CMD_STORAGE_IMPORT_REQ			0x36
#define AHAB_SHE_CMD_CIPHER_REQ					0x37


#define AHAB_SUCCESS_IND						0x00
#define AHAB_FAILURE_IND						0x29

#define	AHAB_SHE_ERC_SEQUENCE_ERROR_IND         ((0xD1 << 8) | AHAB_FAILURE_IND)		/**< Invalid sequence of commands. */
#define	AHAB_SHE_ERC_KEY_NOT_AVAILABLE_IND      ((0xD2 << 8) | AHAB_FAILURE_IND)	    /**< Key is locked. */
#define	AHAB_SHE_ERC_KEY_INVALID_IND            ((0xD3 << 8) | AHAB_FAILURE_IND)		/**< Key not allowed for the given operation. */
#define	AHAB_SHE_ERC_KEY_EMPTY_IND              ((0xD4 << 8) | AHAB_FAILURE_IND)		/**< Key has not beed initialized yet. */
#define	AHAB_SHE_ERC_NO_SECURE_BOOT_IND         ((0xD5 << 8) | AHAB_FAILURE_IND)		/**< Conditions for a secure boot process are not met. */
#define	AHAB_SHE_ERC_KEY_WRITE_PROTECTED_IND    ((0xD6 << 8) | AHAB_FAILURE_IND)        /**< Memory slot for this key has been write-protected. */
#define	AHAB_SHE_ERC_KEY_UPDATE_ERROR_IND       ((0xD7 << 8) | AHAB_FAILURE_IND)	    /**< Key update did not succeed due to errors in verification of the messages. */
#define	AHAB_SHE_ERC_RNG_SEED_IND               ((0xD8 << 8) | AHAB_FAILURE_IND)		/*< The seed has not been initialized. */
#define	AHAB_SHE_ERC_NO_DEBUGGING_IND           ((0xD9 << 8) | AHAB_FAILURE_IND)		/**< Internal debugging is not possible. */
#define	AHAB_SHE_ERC_BUSY_IND                   ((0xDA << 8) | AHAB_FAILURE_IND)		/**< A function of SHE is called while another function is still processing. */
#define	AHAB_SHE_ERC_MEMORY_FAILURE_IND         ((0xDB << 8) | AHAB_FAILURE_IND)		/**< Memory error (e.g. flipped bits) */
#define	AHAB_SHE_ERC_GENERAL_ERROR_IND          ((0xDC << 8) | AHAB_FAILURE_IND)		/**< Error not covered by other codes occured. */

struct she_mu_hdr {
	uint8_t ver;
	uint8_t size;
	uint8_t command;
	uint8_t tag;
};

/* Fill a command message header with a given command ID and length in bytes. */
static inline void she_fill_cmd_msg_hdr(struct she_mu_hdr *hdr, uint8_t cmd, uint8_t len)
{
	hdr->tag = MESSAGING_TAG_COMMAND;
	hdr->command = cmd;
	hdr->size = len / sizeof(uint32_t);
	hdr->ver = MESSAGING_VERSION_2;
};

/* Fill a response message header with a given command ID and length in bytes. */
static inline void she_fill_rsp_msg_hdr(struct she_mu_hdr *hdr, uint8_t cmd, uint8_t len)
{
	hdr->tag = MESSAGING_TAG_RESPONSE;
	hdr->command = cmd;
	hdr->size = len / sizeof(uint32_t);
	hdr->ver = MESSAGING_VERSION_2;
};


/* MAC generation */

struct she_cmd_generate_mac {
	struct she_mu_hdr hdr;
	uint16_t key_id;
	uint16_t data_length;
	uint16_t data_offset;
	uint16_t mac_offset;
};

struct she_rsp_generate_mac {
	struct she_mu_hdr header;
	uint32_t rsp_code;
};

/* MAC verify */

struct she_cmd_verify_mac{
	struct she_mu_hdr hdr;
	uint16_t key_id;
	uint16_t data_length;
	uint16_t data_offset;
	uint16_t mac_offset;
	uint16_t mac_length;
	uint16_t pad;
};

struct she_rsp_verify_mac{
	struct she_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t verification_status;
};

/* CBC */

struct she_cmd_cipher{
	struct she_mu_hdr hdr;
    uint16_t key_id;
    uint8_t  algo;
    uint8_t  flags;
    uint32_t inputs_address_ext;
    uint32_t outputs_address_ext;
    uint32_t iv_address;
    uint32_t input_address;
    uint32_t output_address;
    uint32_t data_length;
    uint32_t crc;
};
#define SHE_CIPHER_ALGO_ECB 0x00
#define SHE_CIPHER_ALGO_CBC 0x01
#define SHE_CIPHER_FLAG_DECRYPT 0x00
#define SHE_CIPHER_FLAG_ENCRYPT 0x01


struct she_rsp_cipher{
	struct she_mu_hdr hdr;
	uint32_t rsp_code;
};

/* Load key */

struct she_cmd_load_key {
	struct she_mu_hdr hdr;
};

struct she_rsp_load_key  {
	struct she_mu_hdr hdr;
	uint32_t rsp_code;
};

/* SHE inititalization */

struct she_cmd_init {
	struct she_mu_hdr hdr;
};

struct she_rsp_init {
	struct she_mu_hdr hdr;
	uint32_t rsp_code;
	uint16_t shared_buf_offset;
	uint16_t shared_buf_size;
};

struct she_cmd_blob_export_init{
	struct she_mu_hdr hdr;
	uint32_t blob_size;
};

struct she_rsp_blob_export_init{
	struct she_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t load_address_ext;
	uint32_t load_address;
};

struct she_cmd_blob_export {
	struct she_mu_hdr hdr;
};

struct she_rsp_blob_export {
	struct she_mu_hdr hdr;
	uint32_t rsp_code;
};

struct she_cmd_blob_import {
	struct she_mu_hdr hdr;
	uint32_t load_address_ext;
	uint32_t load_address;
	uint32_t blob_size;
};

struct she_rsp_blob_import {
	struct she_mu_hdr hdr;
	uint32_t rsp_code;
};
