// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef SHE_FAST_MAC_H
#define SHE_FAST_MAC_H

#include "internal/she_handle.h"
#include "internal/she_utils.h"

/**
 * @defgroup group15 FAST_MAC
 * \ingroup group100
 * Data description of structures shared with SAB layer, we take
 * same structure from user for SECO and V2X to ease their implementation
 * and differentiate them further in code.
 * @{
 */

#define SHE_FAST_MAC_FLAGS_GENERATION		0
//!< Flag to generate MAC
#define SHE_FAST_MAC_FLAGS_VERIFICATION		1
//!< Flag to verify MAC
#define SHE_FAST_MAC_FLAGS_VERIF_BIT_LEN	2
//!< Flag to verify variable length MAC

/**
 * Structure describing the FAST MAC generation/verification operation arguments
 * for SECO
 */
typedef struct {
	uint16_t key_id;
	//!< identifier of the key to be used for the operation
	uint16_t data_length;
	//!< length in bytes of the input message. The message is padded
	//!< to be a multiple of 128 bits by SHE
	uint16_t data_offset;
	//!< Offset of the Input data in the SECURE RAM
	uint8_t mac_length;
	//!< MAC length in bytes, only valid in case of MAC verification
	uint8_t flags;
	//!< flag to identify the operation(generate/verify)
	uint32_t verification_status;
	//!< result of the MAC comparison
} op_fast_mac_mubuff_t;

/**
 * Structure describing the FAST MAC generation/verification operation arguments
 * for V2X
 */
typedef struct {
	uint16_t key_id;
	//!< identifier of the key to be used for the operation
	uint16_t data_length;
	//!< length in bytes of the input message. The message is padded to be a
	//!< multiple of 128 bits by SHE
	uint16_t rsrv;
	//!< reserved
	uint8_t mac_length;
	//!< MAC length expressed in bits, only valid in case of MAC verification.
	//!< Accepted values are:
	//!<	Zero: the MAC length value used will be the nominal length (128bit).
	//!<	Greater or equal than the minimum value defined in the key store.
	uint8_t flags;
	//!< flag to identify the operation(generate/verify)
	uint32_t m1;
	//!< first 4 bytes of the message to be use for MAC generation/verification
	uint32_t m2;
	//!< 2nd next 4 bytes of the message to be use for MAC generation/verification
	uint32_t m3;
	//!< 3rd next 4 bytes of the message to be use for MAC generation/verification
	uint32_t m4;
	//!< 4th next 4 bytes of the message to be use for MAC generation/verification
	uint32_t verification_status;
	//!< result of the MAC comparison\n
	//!< - 0x5A3CC3A5 - verification success
	//!< - 0 - verification fail
} op_fast_v2x_mac_t;

/** @} end of FAST_MAC group */

/**
 * @defgroup group16 CMD_GENERATE_MAC
 * \ingroup group100
 * SHE supports two types of functions to generate MAC.
 * 1: for 16 bytes message
 * 2: V2-for 16 or greater than 16 bytes message.
 * @{
 */

#define SHE_MAC_SIZE			16u
//!< size of the MAC generated is 128bits.

#define SHE_MESSAGE_OFFSET		16u
//!< message is always kept at offset 16 for FAST MAC V2 API.

/**
 * Structure describing the FAST MAC generation operation arguments
 */
typedef struct {
	uint16_t key_ext;
	//!< identifier of the key extension to be used for the operation
	uint16_t key_id;
	//!< identifier of the key to be used for the operation
	uint16_t message_length;
	//!< length in bytes of the input message. The message is padded to be a
	//!< multiple of 128 bits by SHE
	uint8_t *message;
	//!< pointer to the message to be processed
	uint8_t *mac;
	//!< pointer to where the output MAC should be written
	//!< (128bits should be allocated there)
} op_generate_mac_t;

/**
 * Generates a MAC of a given message with the help of a key identified by key_id.
 *
 * \param utils_handle handle identifying the utils service.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
she_err_t she_generate_mac(she_hdl_t utils_handle, op_generate_mac_t *args);

/**
 * Generates a MAC (V2) of a given message (supports length greater than 16 bytes)
 * with the help of a key identified by key_id.
 *
 * \param utils_handle handle identifying the utils service.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
she_err_t she_generate_fast_mac_mubuff_v2(she_hdl_t utils_handle,
					  op_generate_mac_t *args);

/** @} end of CMD_GENERATE_MAC group */

/**
 * @defgroup group17 CMD_VERIFY_MAC
 * \ingroup group100
 * SHE supports two types of functions to verify MAC.
 * 1: for 16 bytes message
 * 2: V2-for 16 or greater than 16 bytes message.
 * @{
 */

#define SHE_FAST_MAC_VERIFICATION_STATUS_OK	0x5a3cc3a5
//!< verification status of MAC

#define MAC_BYTES_LENGTH		0
//!< MAC length expressed in bytes

#define MAC_BITS_LENGTH			1
//!< MAC length expressed in bits

#define SHE_MAC_VERIFICATION_SUCCESS	0
//!< indication of mac verification success

#define SHE_MAC_VERIFICATION_FAILED	1
//!< indication of mac verification failure

/**
 * Structure describing the FAST MAC generation operation arguments
 */
typedef struct {
	uint16_t key_ext;
	//!< identifier of the key extension to be used for the operation
	uint16_t key_id;
	//!< identifier of the key to be used for the operation
	uint16_t message_length;
	//!< length in bytes of the input message. The message is padded to be a
	//!< multiple of 128 bits by SHE
	uint8_t *message;
	//!< pointer to the message to be processed
	uint8_t *mac;
	//!< pointer to the MAC to be compared
	uint8_t mac_length;
	//!< number of MAC bytes to be compared with the expected value.
	//!< It cannot be lower than 4 bytes.
	uint32_t verification_status;
	//!< result of the MAC comparison
	uint8_t mac_length_encoding;
	//!< mac length expressed in bytes or bits
} op_verify_mac_t;

/**
 * Verify the MAC of a given message with the help of a key identified by key_id.
 *
 * \param utils_handle handle identifying the utils service.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
she_err_t she_verify_mac(she_hdl_t utils_handle, op_verify_mac_t *args);

/**
 * Verify the MAC (V2) of a given message (supports message length greater
 * than 16 bytes) with the help of a key identified by key_id.
 *
 * \param utils_handle handle identifying the utils service.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
she_err_t she_verify_fast_mac_mubuff_v2(she_hdl_t utils_handle, op_verify_mac_t *args);

/** @} end of CMD_GENERATE_MAC group */

#endif
