// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef RNG_H
#define RNG_H

#include <stdint.h>

#ifndef PSA_COMPLIANT
typedef uint8_t svc_rng_flags_t;
typedef struct {
	svc_rng_flags_t flags;
	//!< bitmap indicating the service flow properties
	uint8_t reserved[3];
	uint32_t rng_hdl;
	//!< rng handle
} open_svc_rng_args_t;
#endif

/**
 * Structure detailing the get random number operation member arguments
 */
typedef struct {
	uint8_t *output;
	//!< pointer to the output area where the random number must be written
	uint32_t random_size;
	//!< length in bytes of the random number to be provided.
#ifndef PSA_COMPLIANT
	svc_rng_flags_t svc_flags;
	//!< bitmap indicating the service flow properties
	uint8_t reserved[3];
#endif
} op_get_random_args_t;

#endif
