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

#ifndef HSM_MAC_H
#define HSM_MAC_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_key.h"

/**
 *  @defgroup group16 Mac
 * @{
 */

typedef uint8_t hsm_svc_mac_flags_t;
typedef struct {
	//!< bitmap specifying the services properties.
	hsm_svc_mac_flags_t flags;
	uint8_t reserved[3];
	hsm_hdl_t mac_serv_hdl;
} open_svc_mac_args_t;

/**
 * Open a mac service flow
 *
 * User can call this function only after having opened
 * a key store service flow.\n
 *
 * User must open this service in order to perform mac operation\n
 *
 * \param key_store_hdl handle identifying the key store service flow.
 * \param args pointer to the structure containing the function arguments.
 * \param mac_hdl pointer to where the mac service flow handle must be written.
 *
 * \return error code
 */
hsm_err_t hsm_open_mac_service(hsm_hdl_t key_store_hdl,
			       open_svc_mac_args_t *args,
			       hsm_hdl_t *mac_hdl);


typedef uint8_t hsm_op_mac_one_go_flags_t;
#define HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION \
				((hsm_op_mac_one_go_flags_t)(0u << 0))
#define HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION \
				((hsm_op_mac_one_go_flags_t)(1u << 0))

#ifndef PSA_COMPLIANT
#define HSM_OP_MAC_ONE_GO_FLAGS_MAC_LENGTH_IN_BITS \
				((hsm_op_mac_one_go_flags_t)(1u << 1))
#define HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC \
				((hsm_op_mac_one_go_algo_t)(0x01u))
#define HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_224 \
				((hsm_op_mac_one_go_algo_t)(0x05u))
#define HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_256 \
				((hsm_op_mac_one_go_algo_t)(0x06u))
#define HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_384 \
				((hsm_op_mac_one_go_algo_t)(0x07u))
#define HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_512 \
				((hsm_op_mac_one_go_algo_t)(0x08u))
#endif

typedef uint32_t hsm_mac_verification_status_t;
#define HSM_MAC_VERIFICATION_STATUS_SUCCESS \
				((hsm_mac_verification_status_t)(0x6C1AA1C6u))

#ifdef PSA_COMPLIANT
//!< Following three permitted algos are allowed:
//   -  PERMITTED_ALGO_HMAC_SHA256			= 0x03800009,
//   -	PERMITTED_ALGO_HMAC_SHA384			= 0x0380000A,
//   -	PERMITTED_ALGO_CMAC				= 0x03C00200,
typedef hsm_permitted_algo_t hsm_op_mac_one_go_algo_t;
#else
typedef uint8_t hsm_op_mac_one_go_algo_t;
#endif

typedef struct {
	//!< identifier of the key to be used for the operation
	uint32_t key_identifier;
	//!< algorithm to be used for the operation
	hsm_op_mac_one_go_algo_t algorithm;
	//!< bitmap specifying the operation attributes
	hsm_op_mac_one_go_flags_t flags;
	//!< pointer to the payload area\n
	uint8_t *payload;
	//!< pointer to the tag area\n
	uint8_t *mac;
	//!< length in bytes of the payload
	uint16_t payload_size;
	//!< length of the tag.
	//   - Specified in bytes if HSM_OP_MAC_ONE_GO_FLAGS_MAC_LENGTH_IN_BITS
	//     is clear.
	//   - Specified in bits when HSM_OP_MAC_ONE_GO_FLAGS_MAC_LENGTH_IN_BITS
	//     is set.
	//   Note:
	//   - When specified in bytes the mac size cannot be less than 4 bytes.
	//   - When specified in bits the mac size cannot be less than:
	//     -- the key specific min_mac_len setting if specified for this key
	//        when generated/injected; or
	//     -- the min_mac_length value if specified at the key store
	//        provisioning.
	//        (if a key specific setting was not specified at key
	//         generation/injection); or
	//     -- the default value (32 bit) if a minimum has not been specified
	//        using one of the above 2 methods.
	uint16_t mac_size;
	hsm_mac_verification_status_t verification_status;
} op_mac_one_go_args_t;

/**
 * Perform mac operation\n
 * User can call this function only after having opened a mac service flow\n
 *
 * For CMAC algorithm, a key of type HSM_KEY_TYPE_AES_XXX must be used\n
 *
 * For HMAC algorithm, a key of type HSM_KEY_TYPE_HMAC_XXX must be used\n
 *
 * For mac verification operations, the verified mac length can be specified in:
 * - Bits by setting the HSM_OP_MAC_ONE_GO_FLAGS_MAC_LENGTH_IN_BITS flag,
 * - if this flag is clear then the mac_length is specified in bytes.
 *
 * For mac generation operations:
 * - mac length must be set in bytes, and
 * - HSM_OP_MAC_ONE_GO_FLAGS_MAC_LENGTH_IN_BITS flag must be 0\n
 *
 * \param mac_hdl handle identifying the mac service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_mac_one_go(hsm_hdl_t mac_hdl, op_mac_one_go_args_t *args,
			 hsm_mac_verification_status_t *status);


/**
 * Terminate a previously opened mac service flow
 *
 * \param mac_hdl: pointer to handle identifying the mac service flow
 *                 to be closed.
 *
 * \return error code
 */
hsm_err_t hsm_close_mac_service(hsm_hdl_t mac_hdl);

/**
 *\addtogroup qxp_specific
 * \ref group16
 *
 * - \ref HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_224 is not supported.
 * - \ref HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_256 is not supported.
 * - \ref HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_384 is not supported.
 * - \ref HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_512 is not supported.
 *
 */

/**
 *\addtogroup dxl_specific
 * \ref group16
 *
 * - \ref HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_224 is not supported.
 * - \ref HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_256 is not supported.
 * - \ref HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_384 is not supported.
 * - \ref HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_512 is not supported.
 *
 */

/** @} end of mac service flow */
#endif
