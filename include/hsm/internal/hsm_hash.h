/*
 * Copyright 2022 NXP
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
typedef uint8_t hsm_svc_hash_flags_t;
typedef struct {
	hsm_hdl_t hash_hdl;
	//!< bitmap indicating the service flow properties
	hsm_svc_hash_flags_t flags;
	uint8_t reserved[3];
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
	HSM_HASH_ALGO_SM3_256 = 0x02000014,
} hsm_hash_algo_t;

#else

typedef uint8_t hsm_hash_algo_t;
#define HSM_HASH_ALGO_SHA_224      ((hsm_hash_algo_t)(0x0u))
#define HSM_HASH_ALGO_SHA_256      ((hsm_hash_algo_t)(0x1u))
#define HSM_HASH_ALGO_SHA_384      ((hsm_hash_algo_t)(0x2u))
#define HSM_HASH_ALGO_SHA_512      ((hsm_hash_algo_t)(0x3u))
#define HSM_HASH_ALGO_SM3_256      ((hsm_hash_algo_t)(0x11u))

#endif

typedef uint8_t hsm_op_hash_one_go_flags_t;

typedef struct {
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
	//!< flags bitmap specifying the operation attributes.
	hsm_op_hash_one_go_flags_t flags;
	uint16_t reserved;
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
