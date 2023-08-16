// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_CIPHER_H
#define SHE_CIPHER_H

#include "internal/she_handle.h"
#include "common/cipher.h"

/**
 * @defgroup group10 CMD_ENC_CBC / CMD_DEC_CBC and CMD_ENC_ECB / CMD_DEC_ECB
 * \ingroup group100
 * @{
 */

/**
 * - Open a cipher service flow.
 * - User can call this function only after having opened a key-store
 *   service flow.
 * - User must open this service in order to perform cipher operation.
 *
 * \param session_hdl: handle identifying the SHE session.
 * \param args: pointer to the structure containing the function arguments.
 *
 * \return error code.
 */
she_err_t she_open_cipher_service(she_hdl_t session_hdl,
				  open_svc_cipher_args_t *args);

/**
 * Terminate a previously opened cipher service flow
 *
 * \param session_hdl: pointer to handle identifying the SHE session.
 *
 * \return error code.
 */
she_err_t she_close_cipher_service(she_hdl_t session_hdl);

/**
 * Bit field indicating the requested cipher operations
 */
typedef uint8_t she_op_cipher_one_go_algo_t;

#define SHE_CIPHER_ONE_GO_ALGO_AES_ECB \
				((she_op_cipher_one_go_algo_t)(0x00u))
#define SHE_CIPHER_ONE_GO_ALGO_AES_CBC \
				((she_op_cipher_one_go_algo_t)(0x01u))

/**
 * Perform AES CCM with following constraints:
 *  - AES CCM where:
 *    -- Adata = 0,
 *    -- Tlen = 16 bytes,
 *    -- nonce size = 12 bytes
 */
#define SHE_CIPHER_ONE_GO_ALGO_AES_CCM \
				((she_op_cipher_one_go_algo_t)(0x04u))
#define SHE_CIPHER_ONE_GO_ALGO_SM4_ECB \
				((she_op_cipher_one_go_algo_t)(0x10u))
#define SHE_CIPHER_ONE_GO_ALGO_SM4_CBC \
				((she_op_cipher_one_go_algo_t)(0x11u))

/**
 * Bit field indicating the requested encrypt/decrypt operations
 */
typedef uint8_t she_op_cipher_one_go_flags_t;
/**
 * Bit indicating the decrypt operation
 */
#define SHE_CIPHER_ONE_GO_FLAGS_DECRYPT \
				((she_op_cipher_one_go_flags_t)(0u << 0))
/**
 * Bit indicating the encrypt operation
 */
#define SHE_CIPHER_ONE_GO_FLAGS_ENCRYPT \
				((she_op_cipher_one_go_flags_t)(1u << 0))

/**
 * Perform ciphering operation i.e.
 *
 * CBC encryption/decryption and ECB encryption/decryption of a given
 * plaintext/ciphertext with the key identified by key_id.
 *
 * User can call this function only after having opened a cipher service flow
 *
 * \param session_hdl: handle identifying the SHE session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
she_err_t she_cipher_one_go(she_hdl_t session_hdl, op_cipher_one_go_args_t *args);

/** @} end of Ciphering */
#endif
