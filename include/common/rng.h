// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024, 2026 NXP
 */

#ifndef RNG_H
#define RNG_H

#include <stdint.h>

/**
 *  @defgroup group7 Random number generation
 * @{
 */

#ifndef PSA_COMPLIANT
typedef uint8_t svc_rng_flags_t;
/**
 * Structure detailing session open operation member arguments
 */
typedef struct {
	svc_rng_flags_t flags;
	//!< bitmap indicating the service flow properties
	uint8_t reserved[3];
	//!< reserved bits
	uint32_t rng_hdl;
	//!< rng handle
} open_svc_rng_args_t;
#else
/**
 * Bitmap specifying the RNG operation properties
 */
typedef uint16_t hsm_op_rng_flags_t;

/**
 * Bit field indicating the RNG non-blocking reseed operation.
 * DRBG instance is reseeded using ELE TRNG.
 */
#define HSM_OP_RNG_FLAGS_RESEED_NON_BLOCKING ((hsm_op_rng_flags_t)(1u << 0))

/**
 * Bit field indicating the RNG blocking reseed operation.
 */
#define HSM_OP_RNG_FLAGS_RESEED_BLOCKING ((hsm_op_rng_flags_t)(1u << 1))
#endif

/**
 * Structure detailing the get random number operation member arguments
 */
typedef struct {
	uint8_t *output;
	//!< pointer to the output area where the random number must be written
	uint32_t random_size;
	//!< length in bytes of the random number to be provided.
#ifdef PSA_COMPLIANT
	hsm_op_rng_flags_t flags;
	//!< Bit 0: Non-blocking Reseed flag.
	//!< Bit 1: Blocking Reseed flag.
	//!< Notes:
	//!<  - Bit 0 and Bit 1 are exclusive. If no flag is set,
	//!<    no reseed happens (regular random number generation).
	//!<  - If one of the flag is set and output size is not 0, first
	//!<    reseed will be done, and then execution of the RNG operation.
	//!<  - If one of the flag is set and output size is 0, then only the
	//!<    reseed operation will be performed.
#else
	svc_rng_flags_t svc_flags;
	//!< bitmap indicating the service flow properties
	uint8_t reserved[3];
	//!< reserved bits
#endif
} op_get_random_args_t;

/** @} end of rng service flow */
#endif
