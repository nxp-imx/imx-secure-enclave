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

#ifndef HSM_RNG_H
#define HSM_RNG_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_key.h"

/**
 *  @defgroup group7 Random number generation
 * @{
 */

typedef uint8_t hsm_svc_rng_flags_t;
typedef struct {
	//!< bitmap indicating the service flow properties
	hsm_svc_rng_flags_t flags;
	uint8_t reserved[3];
} open_svc_rng_args_t;

/**
 * Open a random number generation service flow\n
 * User can call this function only after having opened a session.\n
 * User must open this service in order to perform rng operations.
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 * \param rng_hdl pointer to where the rng service flow handle must be written.
 *
 * \return error code
 */
hsm_err_t hsm_open_rng_service(hsm_hdl_t session_hdl, open_svc_rng_args_t *args, hsm_hdl_t *rng_hdl);

/**
 * Terminate a previously opened rng service flow
 *
 * \param rng_hdl handle identifying the rng service flow to be closed.
 *
 * \return error code
 */
hsm_err_t hsm_close_rng_service(hsm_hdl_t rng_hdl);

typedef struct {
	uint8_t *output;                        //!< pointer to the output area where the random number must be written
	uint32_t random_size;                   //!< length in bytes of the random number to be provided.
	//!< bitmap indicating the service flow properties
	hsm_svc_rng_flags_t svc_flags;
	uint8_t reserved[3];
} op_get_random_args_t;

/**
 * Get a freshly generated random number\n
 * User can call this function only after having opened a rng service flow
 *
 * \param rng_hdl handle identifying the rng service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_get_random(hsm_hdl_t rng_hdl, op_get_random_args_t *args);
/** @} end of rng service flow */
#endif
