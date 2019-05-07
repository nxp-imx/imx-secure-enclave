/*
 * Copyright 2019 NXP
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef SECO_IOCTL_H
#define SECO_IOCTL_H

/* IOCTL definitions. */

struct seco_ioctl_she_storage_create {
	uint32_t key_storage_identifier;
	uint32_t password;
	uint16_t max_updates_number;
	uint8_t *signed_message;
	uint32_t msg_len;
	uint32_t error_code;
};

struct seco_ioctl_she_open_session {
	uint32_t key_storage_identifier;
	uint32_t password;
	uint32_t error_code;
};

struct seco_ioctl_she_generate_mac {
	uint8_t key_ext;
	uint8_t key_id;
	uint16_t message_length;
	uint8_t *message;
	uint8_t *mac;
	uint32_t err;
};

struct seco_ioctl_she_verify_mac {
	uint8_t key_ext;
	uint8_t key_id;
	uint16_t message_length;
	uint8_t *message;
	uint8_t *mac;
	uint8_t mac_length;
	uint8_t verification_status;
	uint32_t err;
};

struct seco_ioctl_she_enc_cbc {
	uint8_t key_ext;
	uint8_t key_id;
	uint32_t data_length;
	uint8_t *iv;
	uint8_t *plaintext;
	uint8_t *ciphertext;
	uint32_t err;
};

struct seco_ioctl_she_dec_cbc {
	uint8_t key_ext;
	uint8_t key_id;
	uint32_t data_length;
	uint8_t *iv;
	uint8_t *ciphertext;
	uint8_t *plaintext;
	uint32_t err;
};

struct seco_ioctl_she_enc_ecb {
	uint8_t key_ext;
	uint8_t key_id;
	uint8_t *plaintext;
	uint8_t *ciphertext;
	uint32_t err;
};

struct seco_ioctl_she_dec_ecb {
	uint8_t key_ext;
	uint8_t key_id;
	uint8_t *ciphertext;
	uint8_t *plaintext;
	uint32_t err;
};

struct seco_ioctl_she_load_key {
	uint8_t key_ext;
	uint8_t key_id;
	uint8_t *m1;
	uint8_t *m2;
	uint8_t *m3;
	uint8_t *m4;
	uint8_t *m5;
	uint32_t err;
};

struct seco_ioctl_she_load_plain_key {
	uint8_t *key;
	uint32_t err;
};

struct seco_ioctl_she_export_ram_key {
	uint8_t *m1;
	uint8_t *m2;
	uint8_t *m3;
	uint8_t *m4;
	uint8_t *m5;
	uint32_t err;
};

struct seco_ioctl_she_init_rng {
	uint32_t err;
};

struct seco_ioctl_she_extend_seed {
	uint8_t *entropy;
	uint32_t err;
};

struct seco_ioctl_she_generate_rnd {
	uint8_t *rnd;
	uint32_t err;
};

struct seco_ioctl_she_get_status {
	uint8_t sreg;
	uint32_t err;
};

struct seco_ioctl_she_get_id {
	uint8_t *challenge;
	uint8_t *id;
	uint8_t sreg;
	uint8_t *mac;
	uint32_t err;
};

struct seco_ioctl_she_cancel {
	uint32_t err;
};

struct seco_ioctl_nvm_open_session {
	uint32_t flags;
	uint8_t *data;
	uint32_t len;
	uint32_t error_code;
};

struct seco_ioctl_nvm_get_data_len {
	uint32_t data_len;
};

struct seco_ioctl_nvm_get_data {
	uint8_t *dst;
	uint32_t export_status;
	uint32_t error;
};

struct seco_ioctl_nvm_write_status {
	uint32_t error;
};

struct seco_ioctl_hsm_open_session {
	uint8_t session_priority;
	uint8_t operating_mode;
	uint32_t session_hdl;
	uint32_t error;
};

struct seco_ioctl_hsm_close_session {
	uint32_t session_hdl;
	uint32_t error;
};

#define SECO_MU_IOCTL			0x0A /* like MISC_MAJOR. */

#define SECO_MU_IOCTL_SHE_STORAGE_CREATE _IOWR(SECO_MU_IOCTL, 0x01, \
			struct seco_ioctl_she_storage_create)
#define SECO_MU_IOCTL_SHE_OPEN_SESSION   _IOWR(SECO_MU_IOCTL, 0x02, \
			struct seco_ioctl_she_open_session)
#define SECO_MU_IOCTL_SHE_CLOSE_SESSION  _IO(SECO_MU_IOCTL, 0x03)
#define SECO_MU_IOCTL_SHE_GENERATE_MAC   _IOWR(SECO_MU_IOCTL, 0x04, \
			struct seco_ioctl_she_generate_mac)
#define SECO_MU_IOCTL_SHE_VERIFY_MAC     _IOWR(SECO_MU_IOCTL, 0x05, \
			struct seco_ioctl_she_verify_mac)
#define SECO_MU_IOCTL_SHE_ENC_CBC        _IOWR(SECO_MU_IOCTL, 0x06, \
			struct seco_ioctl_she_enc_cbc)
#define SECO_MU_IOCTL_SHE_DEC_CBC        _IOWR(SECO_MU_IOCTL, 0x07, \
			struct seco_ioctl_she_dec_cbc)
#define SECO_MU_IOCTL_SHE_ENC_ECB        _IOWR(SECO_MU_IOCTL, 0x08, \
			struct seco_ioctl_she_enc_ecb)
#define SECO_MU_IOCTL_SHE_DEC_ECB        _IOWR(SECO_MU_IOCTL, 0x09, \
			struct seco_ioctl_she_dec_ecb)
#define SECO_MU_IOCTL_SHE_LOAD_KEY       _IOWR(SECO_MU_IOCTL, 0x0A, \
			struct seco_ioctl_she_load_key)
#define SECO_MU_IOCTL_SHE_LOAD_PLAIN_KEY _IOWR(SECO_MU_IOCTL, 0x0B, \
			struct seco_ioctl_she_load_plain_key)
#define SECO_MU_IOCTL_SHE_EXPORT_RAM_KEY _IOWR(SECO_MU_IOCTL, 0x0C, \
			struct seco_ioctl_she_export_ram_key)
#define SECO_MU_IOCTL_SHE_INIT_RNG       _IOR(SECO_MU_IOCTL, 0x0D,  \
			struct seco_ioctl_she_init_rng)
#define SECO_MU_IOCTL_SHE_EXTEND_SEED    _IOWR(SECO_MU_IOCTL, 0x0E, \
			struct seco_ioctl_she_extend_seed)
#define SECO_MU_IOCTL_SHE_GENERATE_RND   _IOWR(SECO_MU_IOCTL, 0x0F, \
			struct seco_ioctl_she_generate_rnd)
#define SECO_MU_IOCTL_SHE_GET_STATUS     _IOR(SECO_MU_IOCTL, 0x10,  \
			struct seco_ioctl_she_get_status)
#define SECO_MU_IOCTL_SHE_GET_ID         _IOWR(SECO_MU_IOCTL, 0x11, \
			struct seco_ioctl_she_get_id)
#define SECO_MU_IOCTL_SHE_CANCEL         _IOR(SECO_MU_IOCTL, 0x12,  \
			struct seco_ioctl_she_get_id)

#define SECO_MU_IOCTL_NVM_OPEN_SESSION   _IOWR(SECO_MU_IOCTL, 0x20, \
			struct seco_ioctl_she_get_id)
#define SECO_MU_IOCTL_NVM_CLOSE_SESSION  _IO(SECO_MU_IOCTL, 0x21)
#define SECO_MU_IOCTL_NVM_GET_DATA_LEN   _IOR(SECO_MU_IOCTL, 0x22,  \
			struct seco_ioctl_nvm_get_data_len)
#define SECO_MU_IOCTL_NVM_GET_DATA       _IOWR(SECO_MU_IOCTL, 0x23, \
			struct seco_ioctl_nvm_get_data)
#define SECO_MU_IOCTL_NVM_WRITE_STATUS   _IOWR(SECO_MU_IOCTL, 0x24, \
			struct seco_ioctl_nvm_write_status)


#define SECO_MU_IOCTL_HSM_OPEN_SESSION   _IOWR(SECO_MU_IOCTL, 0x30, \
			struct seco_ioctl_hsm_open_session)
#define SECO_MU_IOCTL_HSM_CLOSE_SESSION  _IOR(SECO_MU_IOCTL, 0x31,  \
			struct seco_ioctl_hsm_close_session)

#endif
