// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_GET_ID_H
#define SHE_GET_ID_H

#include "internal/she_handle.h"
#include "internal/she_utils.h"

/**
 * @defgroup group16 CMD_GET_ID
 * \ingroup group100
 * @{
 */

#define SHE_CHALLENGE_SIZE	16u	/* 128 bits */
//!< size of the input challenge vector is 128 bits.
#define SHE_ID_SIZE		15u	/* 120 bits */
//!< size of the Identity(ID) returned is 120 bits.
#define SHE_MAC_SIZE		16u	/* 128 bits */
//!< size of the computed MAC is 128 bits.

/**
 * Structure describing the fast mac generation operation arguments for SECO
 */
typedef struct {
	uint8_t challenge[SHE_CHALLENGE_SIZE];
	//!< Challenge vector
	uint8_t id[SHE_ID_SIZE];
	//!< identity (UID) returned by the command
	uint8_t sreg;
	//!< status register returned by the command
	uint8_t mac[SHE_MAC_SIZE];
	//!< MAC returned by the command
} op_get_id_args_t;

/**
 * This function returns the identity (UID) and the value of the status register protected
 * by a MAC over a challenge and the data.
 * User can call this function only after getting the utility service.
 *
 * \param utils_handle handle identifying the utils service.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

she_err_t she_get_id(she_hdl_t utils_handle, op_get_id_args_t *args);

/** @} end of SHE get id group */
#endif
