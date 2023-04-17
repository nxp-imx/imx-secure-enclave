// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_GC_AKEY_GEN_H
#define HSM_GC_AKEY_GEN_H

#include "internal/hsm_key.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"

/**
 *	@defgroup group23 Generic Crypto Asymmetric Key Generate
 * @{
 */
typedef struct {
	//!< pointer to the output buffer of key modulus
	uint8_t *modulus;
	//!< pointer to the output buffer of key private exponent
	uint8_t *priv_buff;
	//!< pointer to the input buffer containing key public exponent
	uint8_t *pub_buff;
	//!< size in bytes of the modulus buffer
	uint16_t modulus_size;
	//!< size in bytes of the private exponent buffer
	uint16_t priv_buff_size;
	//!< size in bytes of the public exponent buffer
	uint16_t pub_buff_size;
	//!< indicates which type of keypair must be generated
	hsm_key_type_t key_type;
	//!< size in bits of the keypair to be generated
	hsm_bit_key_sz_t bit_key_sz;
} op_gc_akey_gen_args_t;

/**
 * This command is designed to perform the following operations:
 *	-Generate asymmetric keys, without using FW keystore
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_gc_akey_gen(hsm_hdl_t session_hdl, op_gc_akey_gen_args_t *args);
/** @} end of generic crypto asymmetric key generate service flow */
#endif
