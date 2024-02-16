// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef SHE_CIPHER_H
#define SHE_CIPHER_H

#include "internal/she_handle.h"
#include "common/cipher.h"

/**
 * @defgroup group4 CMD_ENC_CBC / CMD_DEC_CBC and CMD_ENC_ECB / CMD_DEC_ECB
 * \ingroup group100
 * @{
 * SHE supports two modes electronic cipher book mode (ECB) for processing
 * single blocks of data and the cipher block chaining mode (CBC) for processing larger
 * amounts of data.
 */

/**
 * Open a cipher service flow.
 * User can call this function only after having opened a key-store
 * service flow.
 * User must open this service in order to perform cipher operation.
 *
 * \param session_hdl handle identifying the SHE session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code.
 */
she_err_t she_open_cipher_service(she_hdl_t session_hdl,
				  open_svc_cipher_args_t *args);

/**
 * Terminate a previously opened cipher service flow
 *
 * \param cipher_handle: handle identifying the Cipher service.
 *
 * \return error code.
 */
she_err_t she_close_cipher_service(she_hdl_t cipher_handle);

typedef uint8_t she_op_cipher_one_go_algo_t;
//!< Bit field indicating the requested cipher operations

#define SHE_CIPHER_ONE_GO_ALGO_AES_ECB \
				((she_op_cipher_one_go_algo_t)(0x00u))
//!< Indicates it is AES ECB Cipher operation
#define SHE_CIPHER_ONE_GO_ALGO_AES_CBC \
				((she_op_cipher_one_go_algo_t)(0x01u))
//!< Indicates it is AES CBC Cipher operation

typedef uint8_t she_op_cipher_one_go_flags_t;
//!< Bit field indicating the requested encrypt/decrypt operations

#define SHE_CIPHER_ONE_GO_FLAGS_DECRYPT \
				((she_op_cipher_one_go_flags_t)(0u << 0))
//!< Bit indicating the decrypt operation
#define SHE_CIPHER_ONE_GO_FLAGS_ENCRYPT \
				((she_op_cipher_one_go_flags_t)(1u << 0))
//!< Bit indicating the encrypt operation

/**
 * Perform ciphering operation i.e.
 *
 * CBC encryption/decryption and ECB encryption/decryption of a given
 * plaintext/ciphertext with the key identified by key_id.
 *
 * User can call this function only after having opened a cipher service flow
 *
 * \param cipher_handle handle identifying the cipher service.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
she_err_t she_cipher_one_go(she_hdl_t cipher_handle, op_cipher_one_go_args_t *args);

/** @} end of Ciphering */
#endif
