// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef SHE_UTILS_H
#define SHE_UTILS_H

#include <stdint.h>
#include "common/err.h"
#include "common/global_info.h"

#define SHE_PREPARE	0x66
#define SHE_RESPONSE	0x99

/**
 * @defgroup group0 Error codes
 * Error codes returned by SHE functions.
 *
 * Details on all error codes returned by SHE APIs
 * @{
 */

/**
 * Error codes returned by SHE functions.
 */
typedef enum {
	SHE_NO_ERROR            = 0x00,
	//!< Success.
	SHE_INVALID_MESSAGE = SAB_INVALID_MESSAGE,
	//!< Invalid/Unknown message.
	SHE_INVALID_ADDRESS = SAB_INVALID_ADDRESS,
	//!< Invalid Address.
	SHE_UNKNOWN_ID = SAB_UNKNOWN_ID,
	//!< Unknown Id.
	SHE_INVALID_PARAM = SAB_INVALID_PARAM,
	//!< MU sanity check failed / Invalid parameters.
	SHE_NVM_ERRO =  SAB_NVM_ERROR,
	//!< NVM general error.
	SHE_OUT_OF_MEMORY = SAB_OUT_OF_MEMORY,
	//!< Internal memory allocation failed.
	SHE_UNKNOWN_HANDLE = SAB_UNKNOWN_HANDLE,
	//!< Unknown handle.
	SHE_UNKNOWN_KEY_STORE = SAB_UNKNOWN_KEY_STORE,
	//!< Key store with provided key store ID does not exist (load operation).
	SHE_KEY_STORE_AUTH = SAB_KEY_STORE_AUTH,
	//!< A key store authentication is failing.
	SHE_KEY_STORAGE_ERROR = SAB_KEY_STORAGE_ERROR,
	//!< Key store creation/load failure.
	SHE_ID_CONFLICT = SAB_ID_CONFLICT,
	//!< A Key store using the same key id already exists (create operation).
	SHE_RNG_NOT_STARTED = SAB_RNG_NOT_STARTED,
	//!< Internal RNG not started.
	SHE_CMD_NOT_SUPPORTED = SAB_CMD_NOT_SUPPORTED,
	//!< Functionality not supported on current service configuration.
	SHE_INVALID_LIFECYCLE = SAB_INVALID_LIFECYCLE,
	//!< Invalid lifecycle for requested operation.
	SHE_KEY_STORE_CONFLICT = SAB_KEY_STORE_CONFLICT,
	//!< The key store already exists (load operation).
	SHE_KEY_STORE_COUNTER = SAB_KEY_STORE_COUNTER,
	//!< Issue occurred while updating the key store counter.
	SHE_FEATURE_NOT_SUPPORTED = SAB_FEATURE_NOT_SUPPORTED,
	//!< Feature is not supported.
	SHE_SELF_TEST_FAILURE = SAB_SELF_TEST_FAILURE,
	//!< Self test execution failed.
	SHE_NOT_READY = SAB_NOT_READY,
	//!< System not ready to accept service request.
	SHE_FEATURE_DISABLED = SAB_FEATURE_DISABLED,
	//!< Feature disabled.
	SHE_UNKNOWN_WARNING = 0x27,
	//!< SHE Unknown Warning
	SHE_SEQUENCE_ERROR_RATING = 0xD1,
	//!< Invalid sequence of commands.
	SHE_KEY_NOT_AVAILABLE_RATING = 0xD2,
	//!< Key is locked.
	SHE_KEY_INVALID_RATING = 0xD3,
	//!< Key not allowed for the given operation.
	SHE_KEY_EMPTY_RATING = 0xD4,
	//!< Key has not been initialized yet.
	SHE_NO_SECURE_BOOT_RATING = 0xD5,
	//!< Conditions for a secure boot process are not met.
	SHE_KEY_WRITE_PROTECTED_RATING = 0xD6,
	//!< Memory slot for this key has been write-protected.
	SHE_KEY_UPDATE_ERROR_RATING = 0xD7,
	//!< Key update did not succeed, errors in verification of message.
	SHE_RNG_SEED_RATING = 0xD8,
	//!< The seed has not been initialized.
	SHE_NO_DEBUGGING_RATING = 0xD9,
	//!< Internal debugging is not possible.
	SHE_BUSY_RATING = 0xDA,
	//!< SHE is busy.
	SHE_MEMORY_FAILURE_RATING = 0xDB,
	//!< Memory Error.
	SHE_GENERAL_ERROR = 0xDC,
	//!< SHE General error.
	SHE_LIB_ERROR = 0xEF,
	//!< SHE library error
	SHE_FATAL_FAILURE = SAB_FATAL_FAILURE,
	//!< fatal error
} she_err_t;

/** @} end of error code group */

she_err_t sab_rating_to_she_err(uint32_t sab_err, void *phdl);

/**
 * maps the plat error to SHE error
 *
 * \param msg_id message id of the message
 * \param lib_err platform API error
 * \param dir direction before/after invoking sab engine
 *
 * \return SHE error code
 */
she_err_t plat_err_to_she_err(uint8_t msg_id, uint32_t lib_err, uint8_t dir);

/**
 * maps the library error to SHE error
 *
 * \param lib_err library error
 *
 * \return SHE error
 */
she_err_t lib_err_to_she_err(uint32_t lib_err);
#endif
