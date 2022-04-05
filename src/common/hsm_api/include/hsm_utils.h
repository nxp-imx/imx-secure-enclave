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

#ifndef HSM_UTILS_H
#define HSM_UTILS_H

#include "stdint.h"

/**
 *  @defgroup group0 Error codes
 *  @{
 */
/**
 * Error codes returned by HSM functions.
 */
typedef enum {
	/**<    Success. */
	HSM_NO_ERROR                        = 0x0,
	/**< 	The received message is invalid or unknown. */
	HSM_INVALID_MESSAGE                 = 0x1,
	/**<	The provided address is invalid or doesn’t respect the
	 *		API requirements. */
	HSM_INVALID_ADDRESS                 = 0x2,
	/**< 	The provided identifier is not known. */
	HSM_UNKNOWN_ID                      = 0x3,
	/**< 	One of the parameter provided in the command is invalid. */
	HSM_INVALID_PARAM                   = 0x4,
	/**< 	NVM generic issue. */
	HSM_NVM_ERROR                       = 0x5,
	/**< 	There is not enough memory to handle the requested operation. */
	HSM_OUT_OF_MEMORY                   = 0x6,
	/**< 	Unknown session/service handle. */
	HSM_UNKNOWN_HANDLE                  = 0x7,
	/**< 	The key store identified by the provided “key store Id”
	 * doesn’t exist and the “create” flag is not set. */
	HSM_UNKNOWN_KEY_STORE               = 0x8,
	/**< 	Key store authentication fails. */
	HSM_KEY_STORE_AUTH                  = 0x9,
	/**< 	An error occurred in the key store internal processing. */
	HSM_KEY_STORE_ERROR                 = 0xA,
	/**< 	An element (key store, key…) with the provided ID
	 * 		already exists. */
	HSM_ID_CONFLICT                     = 0xB,
	/**< 	The internal RNG is not started. */
	HSM_RNG_NOT_STARTED                 = 0xC,
	/**< 	The functionality is not supported for the current
	 * 		session/service/key store configuration. */
	HSM_CMD_NOT_SUPPORTED               = 0xD,
	/**< 	Invalid lifecycle for requested operation. */
	HSM_INVALID_LIFECYCLE               = 0xE,
	/**< 	A key store with the same attributes already exists. */
	HSM_KEY_STORE_CONFLICT              = 0xF,
	/**<	The current key store reaches the max number of
	 * 		monotonic counter updates, updates are still allowed
	 * 		but monotonic counter will not be blown. */
	HSM_KEY_STORE_COUNTER               = 0x10,
	/**<	The requested feature is not supported by the firwware. */
	HSM_FEATURE_NOT_SUPPORTED           = 0x11,
	/**<	Self tests report an issue */
	HSM_SELF_TEST_FAILURE               = 0x12,
	/**<	The HSM is not ready to handle the current request */
	HSM_NOT_READY_RATING                = 0x13,
	/**<	The required service/operation is disabled */
	HSM_FEATURE_DISABLED                = 0x14,
	/**<	A fatal failure occurred, the HSM goes in unrecoverable
	 * 	error state not replying to further requests */
	HSM_FATAL_FAILURE                   = 0x29,
	/**<	Error not covered by other codes occurred. */
	HSM_GENERAL_ERROR                   = 0xFF,
} hsm_err_t;
/** @} end of error code group */

hsm_err_t sab_rating_to_hsm_err(uint32_t sab_err);
#endif
