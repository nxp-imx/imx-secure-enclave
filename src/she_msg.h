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
#include <stdint.h>

#define MESSAGING_TAG_COMMAND			0x17
#define MESSAGING_TAG_RESPONSE			0xe1
#define MESSAGING_VERSION_2				0x2

#define AHAB_SHE_INIT					        0x30
#define AHAB_SHE_CMD_GENERATE_MAC		        0x31
#define AHAB_SHE_CMD_VERIFY_MAC	                0x32
#define AHAB_SHE_CMD_STORAGE_EXPORT_INIT        0x33
#define AHAB_SHE_CMD_LOAD_KEY                   0x34
#define AHAB_SHE_CMD_STORAGE_EXPORT_REQ         0x35
#define AHAB_SHE_CMD_STORAGE_IMPORT_REQ         0x36


#define AHAB_SUCCESS_IND				        0x00


struct she_mu_hdr {
    uint8_t ver;
    uint8_t size;
    uint8_t command;
    uint8_t tag;
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