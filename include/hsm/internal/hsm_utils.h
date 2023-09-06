// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSM_UTILS_H
#define HSM_UTILS_H

#include "stdbool.h"
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

#define HSM_API_VERSION_1    0x1
#define HSM_API_VERSION_2    0x2

/**
 *  @defgroup group30 Global Information
 *  @{
 */

/**
 * Global Information structure contain information about SoC and the Library.
 * It will be used globally to take platform specific decisions.
 */
struct global_info_s {
	bool is_populated;
	//!< to ensure global info is populated once.
	uint8_t ver;
	//!< Supported version of HSM APIs
	uint16_t soc_id;
	//!< SoC ID
	uint16_t soc_rev;
	//!< SoC Revision
	uint16_t lifecycle;
	//!< Device Lifecycle
	uint32_t lib_newness_ver;
	//!< Secure Enclave Library Newness Version
	uint32_t lib_major_ver;
	//!< Secure Enclave Library Major Version
	uint32_t lib_minor_ver;
	//!< Secure Enclave Library Minor Version
	uint32_t nvm_newness_ver;
	//!< NVM Library Newness Version
	uint32_t nvm_major_ver;
	//!< NVM Library Major Version
	uint32_t nvm_minor_ver;
	//!< NVM Library Minor Version
	char se_commit_id[GINFO_COMMIT_ID_SZ];
	//!< Secure Enclave Build Commit ID
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
 * This function returns the version supported for Device Attestation.
 */
uint8_t hsm_get_dev_attest_api_ver(void);

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
/** @} end of global information */

#endif

/**
 *  @defgroup group0 Error codes
 *  @{
 */
/**
 * Error codes returned by HSM functions.
 */
typedef enum {
	HSM_NO_ERROR                        = 0x0,
	/**<Success. */
	HSM_INVALID_MESSAGE                 = 0x1,
	/**<The received message is invalid or unknown. */
	HSM_INVALID_ADDRESS                 = 0x2,
	/**<The provided address is invalid or doesn’t respect the
	 * API requirements.
	 */
	HSM_UNKNOWN_ID                      = 0x3,
	/**<The provided identifier is not known. */
	HSM_INVALID_PARAM                   = 0x4,
	/**<One of the parameter provided in the command is invalid. */
	HSM_NVM_ERROR                       = 0x5,
	/**<NVM generic issue. */
	HSM_OUT_OF_MEMORY                   = 0x6,
	/**<There is not enough memory to handle the requested operation. */
	HSM_UNKNOWN_HANDLE                  = 0x7,
	/**<Unknown session/service handle. */
	HSM_UNKNOWN_KEY_STORE               = 0x8,
	/**<The key store identified by the provided “key store Id”
	 * doesn’t exist and the “create” flag is not set.
	 */
	HSM_KEY_STORE_AUTH                  = 0x9,
	/**<Key store authentication fails. */
	HSM_KEY_STORE_ERROR                 = 0xA,
	/**<An error occurred in the key store internal processing. */
	HSM_ID_CONFLICT                     = 0xB,
	/**<An element (key store, key…) with the provided ID
	 * already exists.
	 */
	HSM_RNG_NOT_STARTED                 = 0xC,
	/**<The internal RNG is not started. */
	HSM_CMD_NOT_SUPPORTED               = 0xD,
	/**<The functionality is not supported for the current
	 * session/service/key store configuration.
	 */
	HSM_INVALID_LIFECYCLE               = 0xE,
	/**<Invalid lifecycle for requested operation. */
	HSM_KEY_STORE_CONFLICT              = 0xF,
	/**<A key store with the same attributes already exists. */
	HSM_KEY_STORE_COUNTER               = 0x10,
	/**<The current key store reaches the max number of
	 * monotonic counter updates, updates are still allowed
	 * but monotonic counter will not be blown.
	 */
	HSM_FEATURE_NOT_SUPPORTED           = 0x11,
	/**<The requested feature is not supported by the firwware. */
	HSM_SELF_TEST_FAILURE               = 0x12,
	/**<Self tests report an issue */
	HSM_NOT_READY_RATING                = 0x13,
	/**<The HSM is not ready to handle the current request */
	HSM_FEATURE_DISABLED                = 0x14,
	/**<The required service/operation is disabled */
	HSM_KEY_GROUP_FULL                  = 0x19,
	/**<Not enough space to store the key in the key group */
	HSM_CANNOT_RETRIEVE_KEY_GROUP       = 0x1A,
	/**<Impossible to retrieve key group */
	HSM_KEY_NOT_SUPPORTED               = 0x1B,
	/**<Key not supported */
	HSM_CANNOT_DELETE_PERMANENT_KEY     = 0x1C,
	/**<Trying to delete a permanent key */
	HSM_OUT_TOO_SMALL                   = 0x1D,
	/**<Output buffer size is too small */
	HSM_DATA_ALREADY_RETRIEVED          = 0x1F,
	/**<Data is Read Once, and has already been retrieved */
	HSM_CRC_CHECK_ERR = 0xB9,
	/**<Command CRC check error */
	HSM_OEM_CLOSED_LC_SIGNED_MSG_VERIFICATION_FAIL = 0xF0,
	/**<In OEM closed lifecycle, Signed message signature verification
	 * failure
	 */
	HSM_OEM_OPEN_LC_SIGNED_MSG_VERIFICATION_FAIL = 0xF0,
	/**<Warning: In OEM open lifecycles, Signed message signature
	 * verification failure
	 */
	HSM_FATAL_FAILURE                   = 0x29,
	/**<A fatal failure occurred, the HSM goes in unrecoverable
	 * error state not replying to further requests
	 */
	HSM_SERVICES_DISABLED               = 0xF4,
	/**<Message neither handled by ROM nor FW */
	HSM_UNKNOWN_WARNING                 = 0xFC,
	/**<Unknown warnings */
	HSM_SIGNATURE_INVALID               = 0xFD,
	/**<Failure in verification status of operations such as
	 * MAC verification, Signature verification.
	 */
	HSM_UNKNOWN_ERROR                   = 0xFE,
	/**<Unknown errors */
	HSM_GENERAL_ERROR                   = 0xFF,
	/**<Error in case General Error is received */
} hsm_err_t;
/** @} end of error code group */

hsm_err_t sab_rating_to_hsm_err(uint32_t sab_err);

#define TLV_LEN_GREATER_THAN_ONE_BYTE           0x80

/**
 * return the number of bytes required for representing length of the
 * length field of the input TLV buffer
 *
 * \param len_buf pointer to the TLV's length buffer
 * \param len_buf_length length of the TLV's length buffer, in bytes
 * \param data_len pointer for getting the data len from length field, in bytes,
 *
 * \return number of bytes representing the length
 */
uint32_t get_tlv_data_len(uint8_t *len_buf,
			  uint32_t len_buf_length,
			  uint32_t *data_len);
/**
 * return the index of the next TLV data buffer
 *
 * \param data pointer to the pointer to get the required data buffer from TLV
 * \param len pointer to get the length of the data being fetched
 * \param tag TAG of the data buffer which is to be fetched from TLV
 * \param tag_len length of the tag in bytes
 * \param tlv_buf pointer to the input TLV buffer
 * \param tlv_buf_len length of the TLV buffer, in bytes
 *
 * \return index of the next TLV data buffer
 */
uint32_t decode_from_tlv_buf(uint8_t **data,
			     uint32_t *len,
			     uint8_t tag,
			     uint8_t tag_len,
			     uint8_t *tlv_buf,
			     uint32_t tlv_buf_len);
#endif
