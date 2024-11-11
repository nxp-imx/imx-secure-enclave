// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#ifndef HSM_MAC_H
#define HSM_MAC_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_key.h"
#include "common/mac.h"

/**
 *  @defgroup group16 Mac
 * @{
 */
#ifndef PSA_COMPLIANT
typedef uint8_t hsm_svc_mac_flags_t;
#endif
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


/**
 * Bitmap describing the mac one go operation
 */
#ifdef PSA_COMPLIANT
typedef uint16_t hsm_op_mac_flags_t;
#else
typedef uint8_t hsm_op_mac_flags_t;
#endif

typedef hsm_op_mac_flags_t hsm_op_mac_one_go_flags_t;

/**
 * Bit indicating MAC Verify operation
 */
#define HSM_OP_MAC_FLAGS_MAC_VERIFICATION \
		MAC_OP_FLAGS_MAC_VERIFICATION
/**
 * Bit indicating MAC Generate operation
 */
#define HSM_OP_MAC_FLAGS_MAC_GENERATION \
		MAC_OP_FLAGS_MAC_GENERATION

/**
 * Bit indicating mac one go verify operation
 */
#define HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION \
				(MAC_OP_FLAGS_MAC_VERIFICATION)
/**
 * Bit indicating mac one go generate operation
 */
#define HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION \
				(MAC_OP_FLAGS_MAC_GENERATION)

#ifdef PSA_COMPLIANT
/**
 * Bit indicating the PLAINTEXT key user input
 */
#define HSM_OP_MAC_FLAGS_PLAINTEXT_KEY \
		MAC_OP_FLAGS_PLAINTEXT_KEY
/**
 * Bit indicating INIT of a multipart context
 */
#define HSM_OP_MAC_FLAGS_INIT \
		((hsm_op_mac_flags_t)(1u << 8))
/**
 * Bit indicating UPDATE DATA to be processed for the multipart operation
 */
#define HSM_OP_MAC_FLAGS_UPDATE_DATA \
		((hsm_op_mac_flags_t)(1u << 10))
/**
 * Bit indicating FINALIZE multipart operation, i.e. MAC Generation
 */
#define HSM_OP_MAC_FLAGS_FINALIZE \
		((hsm_op_mac_flags_t)(1u << 11))
/**
 * Bit indicating FINALIZE VERIFY multipart operation, i.e. Finalize the operation
 * and internal MAC verification
 */
#define HSM_OP_MAC_FLAGS_FINALIZE_VERIFY \
		((hsm_op_mac_flags_t)(1u << 12))
/**
 * Bit indicating ABORT the multipart operation and clean the context
 */
#define HSM_OP_MAC_FLAGS_ABORT \
		((hsm_op_mac_flags_t)(1u << 13))
/**
 * Bit indicating GET CTX SIZE for multipart operation.
 * Size of needed allocated context. Returned in Output size response field.
 */
#define HSM_OP_MAC_FLAGS_GET_CTX_SIZE \
		((hsm_op_mac_flags_t)(1u << 15))

#else
#define HSM_OP_MAC_ONE_GO_FLAGS_MAC_LENGTH_IN_BITS \
				MAC_OP_FLAGS_MAC_LENGTH_IN_BITS
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

/**
 * Bitmap describing the mac verification status
 */
typedef uint32_t hsm_mac_verification_status_t;
/**
 * Bit indicating mac verification success status
 */
#define HSM_MAC_VERIFICATION_STATUS_SUCCESS \
				((hsm_mac_verification_status_t)(0x6C1AA1C6u))
/**
 * Bit indicating mac verification failure status
 */
#define HSM_MAC_VERIFICATION_STATUS_FAILURE \
				((hsm_mac_verification_status_t)(0x0u))

/**
 * Bitmap describing the mac one go operation permitted algorithm
 */
#ifdef PSA_COMPLIANT
//!< Following three permitted algos are allowed:
//!< -  PERMITTED_ALGO_HMAC_SHA256			= 0x03800009,
//!< -	PERMITTED_ALGO_HMAC_SHA384			= 0x0380000A,
//!<  -	PERMITTED_ALGO_CMAC				= 0x03C00200,
typedef hsm_permitted_algo_t hsm_op_mac_algo_t;
#else
typedef uint8_t hsm_op_mac_algo_t;
#endif

typedef hsm_op_mac_algo_t hsm_op_mac_one_go_algo_t;

#ifdef PSA_COMPLIANT
/**
 * Perform mac operation\n
 * User can call this function only after having opened a mac service flow\n
 *
 * \param mac_hdl handle identifying the mac service flow.
 * \param args pointer to the structure containing the function arguments.
 * \param status pointer for storing the verification status.
 *
 * \return error code
 *
 * Note: This API will be deprecated soon.
 */
#else
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
 * \param status pointer for storing the verification status.
 *
 * \return error code
 *
 * Note: This API will be deprecated soon.
 */
#endif
hsm_err_t hsm_mac_one_go(hsm_hdl_t mac_hdl, op_mac_one_go_args_t *args,
			 hsm_mac_verification_status_t *status);
#ifdef PSA_COMPLIANT
/**
 * Perform mac operation\n
 *   - One-Shot mac generation or verification operation using opaque or plaintext key
 *   - Streaming mac generation or verification operation using opaque or plaintext key
 *
 * User can call this function only after having opened a mac service flow\n
 *
 * \param mac_hdl handle identifying the mac service flow.
 * \param args pointer to the structure containing the function arguments.
 * \param status pointer for storing the verification status.
 *
 * \return error code
 */
#else
/**
 * Perform mac operation\n
 *
 * User can call this function only after having opened a mac service flow\n
 *
 * \param mac_hdl handle identifying the mac service flow.
 * \param args pointer to the structure containing the function arguments.
 * \param status pointer for storing the verification status.
 *
 * \return error code
 */

#endif
hsm_err_t hsm_mac(hsm_hdl_t mac_hdl, op_mac_args_t *args,
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
#ifndef PSA_COMPLIANT
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
#endif
/** @} end of mac service flow */
#endif
