// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024, 2026 NXP
 */

#ifndef HSM_GC_AEAD_H
#define HSM_GC_AEAD_H

#include "hsm_key.h"
#include "hsm_utils.h"
#include "hsm_handle.h"

/**
 *	@defgroup group26 Generic Crypto: AEAD
 * @{
 */

/**
 * Enum detailing the generic aead crypto supported algorithms
 */
typedef enum {
	HSM_GC_AEAD_ALGO_AES_GCM = 0x05,
	HSM_GC_AEAD_ALGO_AES_CCM = 0x06,
	HSM_GC_AEAD_ALGO_CHACHA20_POLY1305 = 0x07,
} hsm_op_gc_aead_algo_t;

/**
 * Enum describing the generic aead crypto supported operating modes
 */
typedef enum {
	HSM_GC_AEAD_OP_MODE_ENCRYPT  = 0x41,
	HSM_GC_AEAD_OP_MODE_DECRYPT  = 0x42,
} hsm_gc_aead_op_mode_t;

/**
 * Structure describing the member arguments for generic crypto for aead ops
 */
typedef struct {
	hsm_op_gc_aead_algo_t algorithm;
	//!< algorithm to use for the operation
	hsm_gc_aead_op_mode_t op_mode;
	//!< indicates the operation mode
	uint8_t *in_data_buff;
	//!< pointer to the input data buffer:
	//!<	- plaintext in case of encryption op
	//!<	- encrypted-text in case of decryption op
	uint8_t *out_data_buff;
	//!< pointer to the out data buffer:
	//!<	- ciphertext in case of encryption op
	//!<	- plain-text in case of decryption op
	uint32_t in_data_buff_sz;
	//!< size in bytes of input data buffer
	uint8_t *plain_key_buff;
	//!< pointer to the plain-text key buffer
	uint32_t plain_key_buff_sz;
	//!< size in bytes of plain-text key buffer
	uint8_t *nonce_buff;
	//!< pointer to the nonce buffer.
	uint32_t nonce_sz;
	//!< size in bytes of the nonce buffer
	uint8_t *aad_buff;
	//!< pointer to the authenticated associated data buffer
	uint32_t aad_sz;
	//!< size in bytes of aad buffer
	uint8_t *tag_buff;
	//!< pointer to the tag buffer
	uint32_t tag_sz;
	//!< size in bytes of input data buffer
} op_gc_aead_args_t;

/**
 * This command is designed to perform the following operations:
 *	-AEAD cipher generic crypto operations:
 *		-encryption/decryption
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_gc_aead(hsm_hdl_t session_hdl, op_gc_aead_args_t *args);
/** @} end of generic crypto aead cipher service flow */
#endif
