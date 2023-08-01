// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_KEY_UPDATE_H
#define SHE_KEY_UPDATE_H

#include "internal/she_handle.h"
#include "internal/she_utils.h"

/**
 * @defgroup group9 CMD_LOAD_KEY
 * \ingroup group100
 * @{
 */

/**
 * SHE keys are 128 bits (16 bytes) long.
 */
#define SHE_KEY_SIZE_IN_BYTES	16u

/**
 * Identifiers for SHE keys.
 */
#define SHE_KEY_1	(0x04)
#define SHE_KEY_2	(0x05)
#define SHE_KEY_3	(0x06)
#define SHE_KEY_4	(0x07)
#define SHE_KEY_5	(0x08)
#define SHE_KEY_6	(0x09)
#define SHE_KEY_7	(0x0a)
#define SHE_KEY_8	(0x0b)
#define SHE_KEY_9	(0x0c)
#define SHE_KEY_10	(0x0d)
#define SHE_RAM_KEY	(0x0e)

/**
 * Structure describing the key update operation arguments
 */
typedef struct {
	uint32_t utils_handle;
	//!< Handle to utils service
	uint32_t key_ext;
	//!< identifier of the key extension to be used for the operation
	uint32_t key_id;
	//!< identifier of the key to be used for the operation
	uint8_t *m1;
	//!< pointer to M1 message
	uint8_t m1_size;
	//!< size of M1 message - 128 bits
	uint8_t *m2;
	//!< pointer to M2 message
	uint8_t m2_size;
	//!< size of  M2 message - 256 bits
	uint8_t *m3;
	//!< pointer to M3 message
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
} op_key_update_args_t;

/**
 * Update an internal key of SHE with the protocol specified by SHE.
 * The request is completed only when the new key has been written in the NVM.
 * The monotonic counter is incremented for each successful update.
 *
 * \param session_hdl pointer to the handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
she_err_t she_key_update(she_hdl_t session_hdl, op_key_update_args_t *args);

/** @} end of CMD_LOAD_KEY group */
#endif
