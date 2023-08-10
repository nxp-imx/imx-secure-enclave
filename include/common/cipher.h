// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef CIPHER_H
#define CIPHER_H

#include <stdint.h>

/**
 * Structure describing the open cipher service members
 */
typedef struct {
	uint32_t cipher_hdl;
	//!< handle identifying the cipher service flow
	uint8_t flags;
	//!< bitmap specifying the services properties
	uint8_t reserved[3];
} open_svc_cipher_args_t;

/**
 * Structure describing the cipher one go operation arguments
 */
typedef struct {
	uint32_t key_identifier;
	//!< identifier of the key to be used for the operation
	uint8_t *iv;
	//!< pointer to the initialization vector (nonce in case of AES CCM)
	uint16_t iv_size;
	//!< length in bytes of the initialization vector.
	//   it must be 0 for algorithms not using the initialization vector.
	//   It must be 12 for AES in CCM mode
	uint8_t svc_flags;
	//!< bitmap specifying the services properties.
	uint8_t flags;
	//!< bitmap specifying the operation attributes
#ifdef PSA_COMPLIANT
	uint32_t cipher_algo;
#else
	uint8_t cipher_algo;
#endif
	//!< algorithm to be used for the operation
	uint8_t *input;
	//!< pointer to the input area:
	//   - plaintext for encryption
	//   - ciphertext for decryption
	//     Note: In case of CCM it is the purported ciphertext.
	uint8_t *output;
	//!< pointer to the output area:
	//   - ciphertext for encryption
	//     Note: In case of CCM it is the output of the
	//           generation-encryption process.
	//   - plaintext for decryption
	uint32_t input_size;
	//!< length in bytes of the input.
	//   - In case of CBC and ECB, the input size should be multiple of
	//     a block cipher size (16 bytes).
	uint32_t output_size;
	//!< length in bytes of the output
#ifdef PSA_COMPLIANT
	uint32_t exp_output_size;
	//!< expected output buffer size in bytes, valid in case of (0x1D) error code
#endif
} op_cipher_one_go_args_t;

#endif
