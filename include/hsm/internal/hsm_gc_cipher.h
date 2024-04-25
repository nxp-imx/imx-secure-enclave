// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef HSM_GC_CIPHER_H
#define HSM_GC_CIPHER_H

#include "internal/hsm_key.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"

/**
 *	@defgroup group25 Generic Crypto: Cipher
 * @{
 */

/**
 * Enum detailing the generic crypto supported cipher algorithms
 */
typedef enum {
	HSM_GC_CIPHER_ALGO_AES_ECB_NOPAD = 0x2,
	HSM_GC_CIPHER_ALGO_AES_CBC_NOPAD = 0x3,
} hsm_op_gc_cipher_algo_t;

/**
 * Enum describing the generic cipher crypto supported operating modes
 */
typedef enum {
	HSM_GC_CIPHER_OP_MODE_ENCRYPT  = 0x41,
	HSM_GC_CIPHER_OP_MODE_DECRYPT  = 0x42,
} hsm_gc_cipher_op_mode_t;

/**
 * Structure describing member arguments of generic crypto for cipher ops
 */
typedef struct {
	hsm_op_gc_cipher_algo_t algorithm;
	//!< algorithm to use for the operation
	hsm_gc_cipher_op_mode_t op_mode;
	//!< indicates the operation mode
	uint16_t byte_key_sz;
	//!< key size in bytes
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
	//!< pointer to the data buffer 1:
	uint32_t plain_key_buff_sz;
	//!< size in bytes of input data buffer
	uint8_t *iv_buff;
	//!< pointer to the data buffer 1:
	uint32_t iv_buff_sz;
	//!< size in bytes of input data buffer
} op_gc_cipher_args_t;

/**
 * This command is designed to perform the following operations:
 *	- Cipher Opertions:
 *		-AES ECB encryption/decryption
 *		-AES CBC encryption/decryption
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_gc_cipher(hsm_hdl_t session_hdl, op_gc_cipher_args_t *args);
/** @} end of generic crypto for cipher service flow */
#endif
