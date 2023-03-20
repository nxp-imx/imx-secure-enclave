/*
 * Copyright 2023 NXP
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
