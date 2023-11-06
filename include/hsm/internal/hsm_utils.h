// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef HSM_UTILS_H
#define HSM_UTILS_H

#include "stdint.h"

#include "internal/hsm_handle.h"
#include "common/global_info.h"

#define HSM_PREPARE	0x66
#define HSM_RESPONSE	0x99

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
	HSM_LIB_ERROR                       = 0xEF,
	/**< HSM library failure */
	HSM_INVALID_LIFECYCLE_OP            = 0xF2,
	/**<	Invalid Lifecycle operation (ROM) */
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

/**
 * maps the plat error to HSM error
 *
 * \param msg_id message id of the message
 * \param lib_err platform API error
 * \param dir direction before/after invoking sab engine
 *
 * \return HSM error code
 */
hsm_err_t plat_err_to_hsm_err(uint8_t msg_id, uint32_t lib_err, uint8_t dir);

/**
 * maps the library error to HSM error
 *
 * \param library error
 *
 * \return HSM error code
 */
hsm_err_t lib_err_to_hsm_err(uint32_t lib_err);

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
