// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
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
#ifndef PSA_COMPLIANT
typedef uint8_t hsm_svc_mac_flags_t;
#endif
/**
 * Structure describing the mac open service member agruments
 */
typedef struct {
#ifndef PSA_COMPLIANT
	hsm_svc_mac_flags_t flags;
	//!< bitmap specifying the services properties.
#endif
	hsm_hdl_t mac_serv_hdl;
	//!< indicates the mac handle.
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
		((hsm_op_mac_flags_t)(0u << 0))
/**
 * Bit indicating MAC Generate operation
 */
#define HSM_OP_MAC_FLAGS_MAC_GENERATION \
		((hsm_op_mac_flags_t)(1u << 0))

/**
 * Bit indicating mac one go verify operation
 */
#define HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION \
				(HSM_OP_MAC_FLAGS_MAC_VERIFICATION)
/**
 * Bit indicating mac one go generate operation
 */
#define HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION \
				(HSM_OP_MAC_FLAGS_MAC_GENERATION)

#ifdef PSA_COMPLIANT
/**
 * Bit indicating the PLAINTEXT key user input
 */
#define HSM_OP_MAC_FLAGS_PLAINTEXT_KEY \
		((hsm_op_mac_flags_t)(1u << 3))
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

/**
 * Structure describing the mac operation member agruments
 */
typedef struct {
	uint32_t key_identifier;
	//!< identifier of the key to be used for the operation
#ifdef PSA_COMPLIANT
	//!< The flag for PLAINTEXT key must not be set.
	uint8_t *key;
	//!< pointer to the plaintext key buffer.
	//!< The flag for PLAINTEXT key must be set.
	//!< Only valid for INIT and ONE SHOT operations.
#endif
	hsm_op_mac_algo_t algorithm;
	//!< algorithm to be used for the operation
	hsm_op_mac_flags_t flags;
	//!< bitmap specifying the operation attributes
	uint8_t *payload;
	//!< pointer to the payload area\n
#ifdef PSA_COMPLIANT
	//!< Only valid for UPDATE DATA and ONE SHOT operations.
#endif
	uint8_t *mac;
	//!< pointer to the mac area\n
	//!<   - MAC generation: Output MAC value
	//!<   - MAC verification: Input MAC value to verify
#ifdef PSA_COMPLIANT
	//!< Only valid for FINALIZE, FINALIZE VERIFY and ONE SHOT operations.
#endif
	uint32_t payload_size;
	//!< length in bytes of the payload
#ifdef PSA_COMPLIANT
	//!< Only valid for UPDATE DATA and ONE SHOT operations.
#endif
	uint16_t mac_size;
	//!< length of the MAC.
#ifndef PSA_COMPLIANT
	//!< - Specified in bytes if HSM_OP_MAC_ONE_GO_FLAGS_MAC_LENGTH_IN_BITS
	//!<   is clear.
	//!< - Specified in bits when HSM_OP_MAC_ONE_GO_FLAGS_MAC_LENGTH_IN_BITS
	//!<   is set.
	//!<   Note:
	//!<   - When specified in bytes the mac size cannot be less than 4 bytes.
	//!<   - When specified in bits the mac size cannot be less than:
	//!<     -- the key specific min_mac_len setting if specified for this key
	//!<        when generated/injected; or
	//!<     -- the min_mac_length value if specified at the key store
	//!<        provisioning.
	//!<        (if a key specific setting was not specified at key
	//!<         generation/injection); or
	//!<     -- the default value (32 bit) if a minimum has not been specified
	//!<        using one of the above 2 methods.
#else
	//!< Only valid for FINALIZE, FINALIZE VERIFY and ONE SHOT operations.
	uint16_t key_type;
	//!< Key type. Only valid with PLAINTEXT flag.
	//!< Only valid with ONE SHOT or INIT operations.
	uint16_t key_size;
	//!< Key size in bytes. Only valid with PLAINTEXT flag.
	//!< Only valid with ONE SHOT or INIT operations.
	uint8_t *context;
	//!< Context buffer. Only valid with PLAINTEXT flag.
	uint16_t context_size;
	//!< Size in Bytes of context buffer. Only valid with PLAINTEXT flag.
#endif
	hsm_mac_verification_status_t verification_status;
	//!< mac verification status.
#ifdef PSA_COMPLIANT
	uint16_t exp_mac_size;
	//!< expected mac size for output, returned by FW in case the mac size
	//!<	 provided is less than the expected mac size calculated from MAC
	//!<	 algorithm.
	//!< Note: This field will be deprecated soon. exp_output_size to be
	//!< be used instead.
	uint16_t exp_output_size;
	//!< Expected output buffer size in bytes, valid in case of HSM_OUT_TOO_SMALL
	//!< (0x1D) error code.
	//!< In case of streaming operation, Expected context size in bytes if
	//!< operation failed with 0x1E.
#else
	hsm_svc_mac_flags_t svc_flags;
	//!< bitmap specifying the services properties.
#endif
} op_mac_args_t;

/**
 * Structure describing the mac one go operation member agruments
 */
typedef op_mac_args_t op_mac_one_go_args_t;

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
