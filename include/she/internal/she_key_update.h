// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_KEY_UPDATE_H
#define SHE_KEY_UPDATE_H

#include "internal/she_handle.h"
#include "internal/she_utils.h"
#include "internal/she_key.h"

/**
 * @defgroup group9 CMD_LOAD_KEY
 * \ingroup group100
 * @{
 */

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
 * \param utils_handle handle identifying the utils service.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
she_err_t she_key_update(she_hdl_t utils_handle, op_key_update_args_t *args);

/*
 * User can use this flag to perform multiple updates before writing the key store
 * into the NVM and incrementing the monotonic counter.
 */
#define SHE_LOAD_KEY_EXT_FLAGS_STRICT_OPERATION		BIT(7)

/**
 * Structure describing the key update extension operation arguments
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
	uint8_t flags;
	//!< bitmap specifying the operations property
} op_key_update_ext_args_t;

/**
 * This is an extension of the CMD_LOAD_KEY
 * The functionality of the CMD_LOAD_KEY is extended by adding a flag argument
 * The updates to the key store must be considered as effective only after an
 * operation specifying the flag "STRICT OPERATION" is aknowledged by SHE
 *
 * The request is completed only when the key store is written in the NVM
 * and the monotonic counter is incremented
 *
 * \param utils_handle handle identifying the utils service
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
she_err_t she_key_update_ext(she_hdl_t utils_handle, op_key_update_ext_args_t *args);

/** @} end of CMD_LOAD_KEY group */
#endif
