// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_EXPORT_PLAIN_KEY_H
#define SHE_EXPORT_PLAIN_KEY_H

#include "internal/she_handle.h"
#include "internal/she_utils.h"
#include "internal/she_key.h"

/**
 * @defgroup group14 CMD_EXPORT_RAM_KEY
 * \ingroup group100
 * @{
 */

/**
 * Structure describing the export RAM key operation arguments
 */
typedef struct {
	//!< identifier of the key to be used for the operation
	uint8_t *m1;
	//!< pointer to the output address for M1 message
	uint8_t m1_size;
	//!< size of M1 message - 128 bits
	uint8_t *m2;
	//!< pointer to the output address for M2 message
	uint8_t m2_size;
	//!< size of  M2 message - 256 bits
	uint8_t *m3;
	//!< pointer to the output address for M3 message
	uint8_t m3_size;
	//!< size of M3 message - 128 bits
	uint8_t *m4;
	//!< pointer to the output address for M4 message
	uint8_t m4_size;
	//!< size of M4 message - 256 bits
	uint8_t *m5;
	//!< pointer to the output address for M5 message
	uint8_t m5_size;
	//!< size of M5 message - 128 bits
} op_export_plain_key_args_t;

/**
 * exports the RAM_KEY into a format protected by SECRET_KEY.
 *
 * \param utils_handle handle identifying the SHE utils service.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
she_err_t she_export_plain_key(she_hdl_t utils_handle,
			       op_export_plain_key_args_t *args);

/** @} end of CMD_EXPORT_RAM_KEY group */
#endif
