// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef HSM_KEY_AGREEMENT_H
#define HSM_KEY_AGREEMENT_H

#include "hsm_utils.h"
#include "hsm_common_def.h"

#ifdef PSA_COMPLIANT
/**
 * @defgroup group41 Key Agreement
 * @{
 */

#define HSM_KEY_AGREEMENT_KEY_STORE_ARGS_FORMAT_VERS 0x1u
#define HSM_KEY_AGREEMENT_ALGO_ARGS_ECDH_FORMAT_VERS 0x1u

/**
 * Bitmap specifying the key agreement operation properties
 */
typedef uint16_t hsm_op_key_agreement_flags_t;

/**
 * Bit field indicating the plaintext operation.
 * The private key and shared secret are in user memory.
 */
#define HSM_OP_KEY_AGREEMENT_FLAGS_PLAINTEXT \
	((hsm_op_key_agreement_flags_t)(1u << 0))

/**
 * Bit field indicating the opaque operation.
 * The private key and shared secret are in keystore.
 */
#define HSM_OP_KEY_AGREEMENT_FLAGS_OPAQUE \
	((hsm_op_key_agreement_flags_t)(0u << 0))

/**
 * Enum describing Key Agreement algorithms supported
 */
typedef enum {
	HSM_KEY_AGREEMENT_ECDH = ALGO_ECDH,
	//!< ECDH
} hsm_op_key_agreement_algo_t;

/**
 * Structure representing the Key Agreement arguments for key store (opaque
 * operation), to be used while preparing structure for key agreement operation.
 * Note that this structure format defined to be word-aligned.
 */
typedef struct {
	uint16_t vers;
	//!< The structure version, only 0x1 is supported.
	uint16_t rsv1;
	//!< Reserved.
	uint32_t key_store_id;
	//!< Key store ID that contains the private key and where the shared
	//!< secret will be stored. It must be the key store ID related to the
	//!< key management handle set in the command API.
	uint32_t priv_key_id;
	//!< Key Identifier of the private key to use as key agreement input.
	uint16_t output_key_type;
	//!< Ignored. The shared secret is volatile and cannot be permanently stored.
	//!< It will be key type RAW_DATA.
	uint16_t output_key_bits_sz;
	//!< Output key security size in bits attribute.
	//!< For ECDH must match the size of the input private key.
	uint32_t output_key_lifetime;
	//!< Ignored, will always be standard volatile.
	uint32_t output_key_usage;
	//!< Ignored, will always be Derive & Cache.
	uint32_t output_key_permitted_algo;
	//!< Output key permitted algorithm attribute.
	uint32_t output_key_lifecycle;
	//!< Ignored, key is volatile so only used for current lifecycle.
	uint32_t output_key_id;
	//!< Ignored, FW will always chose the key identifier.
	uint16_t output_key_group;
	//!< Key group the generated shared secret will be stored in.
	uint16_t rsv2;
	//!< Reserved.
} op_key_agreement_key_store_args_t;

/**
 * Structure representing the Key Agreement arguments for ECDH algorithm,
 * to be used while preparing structure for key agreement operation.
 */
typedef struct {
	uint16_t vers;
	//!< The structure version, only 0x1 is supported.
	uint8_t *peer_pub_key;
	//!< Pointer to the peer public key.
	uint32_t peer_pub_key_size;
	//!< Peer public key size in bytes.
	uint8_t *priv_key;
	//!< Pointer to the private key.
	//!< It must be 0 if not plaintext mode.
	uint32_t priv_key_size;
	//!< Private key size in bytes.
	//!< It must be 0 if not plaintext mode.
	uint8_t *shared_secret;
	//!< Pointer to where the shared secret will be output.
	//!< It must be 0 if not plaintext mode.
	uint32_t shared_secret_size;
	//!< Shared secret size in bytes.
	//!< It must be 0 if not plaintext mode.
} op_key_agreement_algo_ecdh_args_t;

/**
 * Structure representing the Key Agreement operation member arguments
 */
typedef struct {
	hsm_op_key_agreement_algo_t algorithm;
	//!< Key agreement algorithm.
	hsm_op_key_agreement_flags_t flags;
	//!< Bit field indicating the requested operations.
	//!< Bit 0: Plaintext operation mode:
	//!<   - 0: private key/shared secret are in keystore.
	//!<   - 1: private key/shared secret are in user memory.
	op_key_agreement_key_store_args_t *key_store_args;
	//!< Pointer to the key store arguments structure.
	//!< It must be NULL in plaintext mode.
	op_key_agreement_algo_ecdh_args_t *key_agreement_algo_args;
	//!< Pointer to the key agreement algorithm arguments structure.
	//!< The structure format is dependent on the algorithm being used.
	uint32_t key_store_args_size;
	//!< Size of the argument structure for the key store in bytes.
	//!< It must be 0x0 in plaintext mode.
	uint32_t key_agreement_algo_args_size;
	//!< Size of the argument structure for the key agreement algorithm in bytes.
	uint32_t shared_secret_key_id;
	//!< The output Key ID of the shared secret when using key store arguments.
	//!< It will be 0x0 in plaintext mode.
} op_key_agreement_args_t;

/**
 * This command is used to perform the Key Agreement operation.
 *
 * It can take the private key from the keystore or in plaintext.
 *   - For plaintext operations, the shared secret output is in user memory.
 *   - For key store based operations, the shared secret is stored in the key store.
 *
 * Note that the shared secret is volatile and cannot be permanently stored.
 *
 * In case of Opaque operation i.e. using key store contents, the key agreement
 * command is only accepted after having opened a valid key management service.
 *
 * \param key_management_hdl handle identifying the key store management service
 * flow in case of opaque key operation. For plaintext mode, key management service
 * flow is not required, SE lib service handle can be used instead.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_key_agreement(hsm_hdl_t key_management_hdl,
			    op_key_agreement_args_t *args);
/** @} end of Key Agreement flow */
#endif
#endif
