// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSM_UTILS_H
#define HSM_UTILS_H

#include "stdint.h"

#ifdef PSA_COMPLIANT
#include "internal/hsm_handle.h"

#define SOC_IMX8ULP 0x84d
#define SOC_IMX93   0x9300

#define SOC_REV_A0  0xa000
#define SOC_REV_A1  0xa100
#define SOC_REV_A2  0xa200

#define SOC_LF_OPEN  0x10
#define SOC_LF_CLOSED 0x20
#define SOC_LF_CLOSED_LOCKED 0x40

#define GINFO_COMMIT_ID_SZ   40

/**
 * Global Information structure contain information about SoC and the Library.
 * It will be used globally to take platform specific decisions.
 */
struct global_info_s {
	//!< SoC ID
	uint16_t soc_id;
	//!< SoC Revision
	uint16_t soc_rev;
	//!< Device Lifecycle
	uint16_t lifecycle;
	//!< Secure Enclave Library Major Version
	uint32_t lib_major_ver;
	//!< Secure Enclave Library Minor Version
	uint32_t lib_minor_ver;
	//!< NVM Library Major Version
	uint32_t nvm_major_ver;
	//!< NVM Library Minor Version
	uint32_t nvm_minor_ver;
	//!< Secure Enclave Build Commit ID
	char se_commit_id[GINFO_COMMIT_ID_SZ];
};

/**
 * Global Information structure instance which will be populated and later be
 * used for getting the required platform or library details.
 */
extern struct global_info_s global_info;

/**
 * This function is called to populate the Global Info structure
 *
 * \param hsm_session_hdl identifying the active session.
 */
void populate_global_info(hsm_hdl_t hsm_session_hdl);
/**
 * This function prints the Global Information of library
 */
void show_global_info(void);
/**
 * This function returns a string representating SoC ID
 *
 * \param soc_id SoC ID fetched from Global Info
 *
 * \return String represention of the SoC ID
 */
const char *get_soc_id_str(uint16_t soc_id);
/**
 * This function returns a string representating SoC Revision
 *
 * \param soc_rev SoC Revision fetched from Global Info
 *
 * \return String represention of the SoC Revision
 */
const char *get_soc_rev_str(uint16_t soc_rev);
/**
 * This function returns a string representating Lifecycle
 *
 * \param lifecycle value fetched from Global Info
 *
 * \return a string represention of Lifecycle
 */
const char *get_soc_lf_str(uint16_t lifecycle);
#endif

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
	/**<	Not enough space to store the key in the key group */
	HSM_KEY_GROUP_FULL                  = 0x19,
	/**<	Impossible to retrieve key group */
	HSM_CANNOT_RETRIEVE_KEY_GROUP       = 0x1A,
	/**<	Key not supported */
	HSM_KEY_NOT_SUPPORTED               = 0x1B,
	/**<	Trying to delete a permanent key */
	HSM_CANNOT_DELETE_PERMANENT_KEY     = 0x1C,
	/**<	Output buffer size is too small */
	HSM_OUT_TOO_SMALL                   = 0x1D,
	/**<	Command CRC check error */
	HSM_CRC_CHECK_ERR                   = 0xB9,
	/**<    In OEM closed lifecycle, Signed message signature verification
	 *      failure
	 */
	HSM_OEM_CLOSED_LC_SIGNED_MSG_VERIFICATION_FAIL = 0xF0,
	/**<    Warning: In OEM open lifecycles, Signed message signature
	 *      verification failure
	 */
	HSM_OEM_OPEN_LC_SIGNED_MSG_VERIFICATION_FAIL = 0xF0,
	/**<	A fatal failure occurred, the HSM goes in unrecoverable
	 * 	error state not replying to further requests */
	HSM_FATAL_FAILURE                   = 0x29,
	/**<	Message neither handled by ROM nor FW */
	HSM_SERVICES_DISABLED               = 0xF4,
	/**<	Unknown warnings */
	HSM_UNKNOWN_WARNING                 = 0xFC,
	/**<    Failure in verification status of operations such as
	 *      MAC verification, Signature verification.
	 */
	HSM_SIGNATURE_INVALID               = 0xFD,
	/**<	Unknown errors */
	HSM_UNKNOWN_ERROR                   = 0xFE,
	/**<	Error in case General Error is received */
	HSM_GENERAL_ERROR                   = 0xFF,
} hsm_err_t;
/** @} end of error code group */

hsm_err_t sab_rating_to_hsm_err(uint32_t sab_err);
#endif
