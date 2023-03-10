/*
 * Copyright 2022-2023 NXP
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

#ifndef HSM_HASH_H
#define HSM_HASH_H

#include <stdint.h>
#include <string.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
/**
 *  @defgroup group8 Hashing
 * @{
 */
typedef struct {
	hsm_hdl_t hash_hdl;
	/*
	 * flags: User input through op args is reserved, as per ELE FW spec.
	 */
} open_svc_hash_args_t;

/**
 * Open an hash service flow\n
 * User can call this function only after having opened a session.\n
 * User must open this service in order to perform hash operations.
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 * \param hash_hdl pointer to where the hash service flow handle must be
 *        written.
 *
 * \return error code
 */
hsm_err_t hsm_open_hash_service(hsm_hdl_t session_hdl,
				open_svc_hash_args_t *args,
				hsm_hdl_t *hash_hdl);

/**
 * Terminate a previously opened hash service flow
 *
 * \param hash_hdl handle identifying the hash service flow to be closed.
 *
 * \return error code
 */
hsm_err_t hsm_close_hash_service(hsm_hdl_t hash_hdl);

#ifdef PSA_COMPLIANT

typedef enum {
	HSM_HASH_ALGO_SHA_224 = 0x02000008,
	HSM_HASH_ALGO_SHA_256 = 0x02000009,
	HSM_HASH_ALGO_SHA_384 = 0x0200000A,
	HSM_HASH_ALGO_SHA_512 = 0x0200000B,
} hsm_hash_algo_t;

#else

typedef uint8_t hsm_hash_algo_t;
#define HSM_HASH_ALGO_SHA_224      ((hsm_hash_algo_t)(0x0u))
#define HSM_HASH_ALGO_SHA_256      ((hsm_hash_algo_t)(0x1u))
#define HSM_HASH_ALGO_SHA_384      ((hsm_hash_algo_t)(0x2u))
#define HSM_HASH_ALGO_SHA_512      ((hsm_hash_algo_t)(0x3u))
#define HSM_HASH_ALGO_SM3_256      ((hsm_hash_algo_t)(0x11u))

#endif

typedef struct {
#ifdef PSA_COMPLIANT
	//!< pointer to the MSB of address in the requester space where buffers
	//can be found, must be 0 until supported.
	uint8_t *msb;
	//!< pointer to the input context buffer to be hashed
	uint8_t *ctx;
#endif
	//!< pointer to the input data to be hashed
	uint8_t *input;
	//!< pointer to the output area where the resulting digest must be written
	uint8_t *output;
	//!< length in bytes of the input
	uint32_t input_size;
	//!< length in bytes of the output
	uint32_t output_size;
	//!< hash algorithm to be used for the operation
	hsm_hash_algo_t algo;
	/*
	 * flags: User input through op args is reserved, as per ELE FW spec.
	 * svc_flags: User input through op args is reserved.
	 */
#ifdef PSA_COMPLIANT
	//!< size of context buffer in bytes, ignored in case of one shot
	//operation.
	uint8_t ctx_size;
	//!< expected output digest buffer size, returned by FW in case the
	//	 provided output size is incorrect.
	uint32_t exp_output_size;
	//!< expected context size to allocate in bytes, if flag Get context
	//	size is set or provided context size is incorrect.
	uint16_t context_size;
#endif
} op_hash_one_go_args_t;

/**
 * Perform the hash operation on a given input\n
 * User can call this function only after having opened a hash service flow
 *
 * \param hash_hdl handle identifying the hash service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_hash_one_go(hsm_hdl_t hash_hdl, op_hash_one_go_args_t *args);

/**
 *\addtogroup qxp_specific
 * \ref group5
 *
 * - \ref HSM_HASH_ALGO_SM3_256 is not supported.
 *
 */
/** @} end of hash service flow */
#endif
