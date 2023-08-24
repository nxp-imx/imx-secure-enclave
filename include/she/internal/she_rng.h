// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_RNG_H
#define SHE_RNG_H

#include "internal/she_handle.h"
#include "internal/she_utils.h"
#include "common/rng.h"

#ifndef PSA_COMPLIANT
/**
 *  @defgroup group6 CMD_INIT_RNG
 *  \ingroup group100
 *  @{
 */
/**
 * initializes the seed and derives a key for the PRNG.
 * The function must be called before CMD_RND after every power cycle/reset.
 *
 * User can call this function only after having opened a session.
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
she_err_t she_open_rng_service(she_hdl_t session_hdl, open_svc_rng_args_t *args);

/**
 * Terminate a previously opened rng service flow
 *
 * \param rng_handle handle identifying the RNG session.
 *
 * \return error code
 */
she_err_t she_close_rng_service(she_hdl_t rng_handle);
/** @} end of CMD_INIT_RNG group */
#endif

/**
 *  @defgroup group7 CMD_RND
 *  \ingroup group100
 *  @{
 */
/**
 * returns a vector of 128 random bits.
 * The random number generator has to be initialized by CMD_INIT_RNG before random
 * numbers can be supplied.
 *
 * \param rng_handle handle identifying the RNG service
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
she_err_t she_get_random(she_hdl_t rng_handle, op_get_random_args_t *args);

/**
 * size of random data for SHE
 */
#define SHE_RND_SIZE 16u

#ifndef PSA_COMPLIANT
/** @} end of CMD_RND group */

/**
 *  @defgroup group8 CMD_EXTEND_SEED
 *  \ingroup group100
 *  @{
 */

/**
 * Structure describing the RNG extend seed operation arguments
 */
typedef struct {
	//!< entropy to extend seed
	uint32_t entropy[4];
	//!< entropy size
	uint32_t entropy_size;
} op_rng_extend_seed_t;

/**
 * extends the seed of the PRNG by compressing the former seed value and the
 * supplied entropy into a new seed which will be used to generate the following
 * random numbers.
 * The random number generator has to be initialized by CMD_INIT_RNG before the
 * seed can be extended.
 *
 * \param rng_handle handle identifying the RNG service
 * \param args pointer to the structure containing entropy vector (128bits)
 *
 * \return error code
 */
she_err_t she_extend_seed(she_hdl_t rng_handle, op_rng_extend_seed_t *args);

/**
 * size of entropy for SHE
 */
#define SHE_ENTROPY_SIZE 16u

/** @} end of CMD_EXTEND_SEED group */
#endif

#endif
