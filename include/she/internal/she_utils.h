// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_UTILS_H
#define SHE_UTILS_H

#include <stdint.h>

/**
 *  @defgroup group100 Error codes
 * Error codes returned by SHE functions.
 *  @{
 */
typedef enum {
	SHE_NO_ERROR            = 0x0, /**< Success. */
	SHE_SEQUENCE_ERROR      = 0x1, /**< Invalid sequence of commands. */
	SHE_KEY_NOT_AVAILABLE   = 0x2, /**< Key is locked. */
	SHE_KEY_INVALID         = 0x3, /**< Key not allowed for the given operation. */
	SHE_KEY_EMPTY           = 0x4, /**< Key has not beed initialized yet. */
	SHE_NO_SECURE_BOOT      = 0x5, /**< Conditions for secure boot process are not met. */
	SHE_KEY_WRITE_PROTECTED = 0x6, /**< Memory slot for key has been write-protected. */
	/**< Key update failed due to errors in verification of the messages. */
	SHE_KEY_UPDATE_ERROR    = 0x7,
	SHE_RNG_SEED            = 0x8, /**< The seed has not been initialized. */
	SHE_NO_DEBUGGING        = 0x9, /**< Internal debugging is not possible. */
	/**< A function of SHE is called while another  function is still processing. */
	SHE_BUSY                = 0xA,
	SHE_MEMORY_FAILURE      = 0xB, /**< Memory error (e.g. flipped bits) */
	SHE_GENERAL_ERROR       = 0xC, /**< Error not covered by other codes occurred. */
	SHE_UNKNOWN_WARNING	= 0x27,	/**< SHE Unknown Warning */
	SHE_FATAL_FAILURE       = 0x29
} she_err_t;
/** @} end of error code group */

she_err_t sab_rating_to_she_err(uint32_t sab_err);
#endif
