// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef HSM_KEY_DERIVATION_H
#define HSM_KEY_DERIVATION_H

#include "hsm_utils.h"
#include "hsm_common_def.h"

#ifdef PSA_COMPLIANT
/**
 * @defgroup group42 Key Derivation
 * @{
 */

#define HSM_KEY_DERIVATION_KEY_STORE_ARGS_FORMAT_VERS 0x1u
#define HSM_KEY_DERIVATION_ALGO_ARGS_HKDF_FORMAT_VERS 0x1u

/**
 * Bitmap specifying the key derivation operation properties
 */
typedef uint16_t hsm_op_key_derivation_flags_t;

/**
 * Bit field indicating the plaintext operation.
 * The IKM/OKM are in user memory.
 */
#define HSM_OP_KEY_DERIVATION_FLAGS_PLAINTEXT \
	((hsm_op_key_derivation_flags_t)(1u << 0))

/**
 * Bit field indicating the opaque operation.
 * The IKM/OKM are in keystore.
 */
#define HSM_OP_KEY_DERIVATION_FLAGS_OPAQUE \
	((hsm_op_key_derivation_flags_t)(0u << 0))

/**
 * Enum describing Key Derivation algorithms supported
 */
typedef enum {
	HSM_KEY_DERIVATION_HKDF_SHA256 = ALGO_HKDF_SHA256,
	//!< HKDF SHA256 (HMAC two-step)
	HSM_KEY_DERIVATION_HKDF_SHA384 = ALGO_HKDF_SHA384,
	//!< HKDF SHA384 (HMAC two-step)
	HSM_KEY_DERIVATION_HKDF_EXTRACT_SHA256 = ALGO_HKDF_EXTRACT_SHA256,
	//!< HKDF Extract SHA256
	HSM_KEY_DERIVATION_HKDF_EXTRACT_SHA384 = ALGO_HKDF_EXTRACT_SHA384,
	//!< HKDF Extract SHA384
	HSM_KEY_DERIVATION_HKDF_EXPAND_SHA256 = ALGO_HKDF_EXPAND_SHA256,
	//!< HKDF Expand SHA256
	HSM_KEY_DERIVATION_HKDF_EXPAND_SHA384 = ALGO_HKDF_EXPAND_SHA384,
	//!< HKDF Expand SHA384
} hsm_op_key_derivation_algo_t;

/**
 * Structure representing the Key Derivation arguments for key store (opaque
 * operation), to be used while preparing structure for key derivation operation.
 * Note that this structure format defined to be word-aligned.
 */
typedef struct {
	uint16_t vers;
	//!< The structure version, only 0x1 is supported.
	uint16_t rsv1;
	//!< Reserved.
	uint32_t key_store_id;
	//!< Key store ID that contains the IKM and where the OKM will be stored.
	//!< It must be the key store ID related to the key management handle set
	//!< in the command API.
	uint32_t key_material_id;
	//!< Key Identifier of the key material to be used as IKM.
	uint16_t derived_key_type;
	//!< Derived key type
	uint16_t derived_key_bits_sz;
	//!< Derived key security size in bits attribute.
	uint32_t derived_key_lifetime;
	//!< Ignored, will always be standard volatile.
	uint32_t derived_key_usage;
	//!< Derived key usage attribute.
	uint32_t derived_key_permitted_algo;
	//!< Derived key permitted algorithm attribute.
	uint32_t derived_key_lifecycle;
	//!< Ignored, key is volatile so only used for current lifecycle.
	uint32_t derived_key_id;
	//!< Ignored, FW will always chose the key identifier.
	uint16_t derived_key_group;
	//!< Key group the derived key will be stored in.
	uint16_t rsv2;
	//!< Reserved.
} op_key_derivation_key_store_args_t;

/**
 * Structure representing the Key Derivation arguments for HKDF algorithm,
 * to be used while preparing structure for key derivation operation.
 */
typedef struct {
	uint16_t vers;
	//!< The structure version, only 0x1 is supported.
	uint8_t *ikm;
	//!< Pointer to the IKM.
	//!< It must be 0 if not plaintext mode.
	uint32_t ikm_size;
	//!< IKM size in bytes.
	//!< It must be 0 if not plaintext mode.
	uint8_t *salt;
	//!< Pointer to the salt data.
	//!< It must be 0 if salt not used.
	uint32_t salt_size;
	//!< Salt data size in bytes.
	//!< It must be 0 if salt not used.
	uint8_t *fixed_info;
	//!< Pointer to the fixed info.
	//!< It must be 0 if not plaintext mode.
	uint32_t fixed_info_size;
	//!< Fixed info size in bytes.
	//!< It must be 0 if not plaintext mode.
	uint8_t *okm;
	//!< Pointer to where the OKM will be output.
	//!< It must be 0 if not plaintext mode.
	uint32_t okm_size;
	//!< OKM size in bytes.
	//!< It must be 0 if not plaintext mode.
} op_key_derivation_algo_hkdf_args_t;

/**
 * Structure representing the Key Agreement operation member arguments
 */
typedef struct {
	hsm_op_key_derivation_algo_t algorithm;
	//!< Key derivation algorithm.
	hsm_op_key_derivation_flags_t flags;
	//!< Bit field indicating the requested operations.
	//!< Bit 0: Plaintext operation mode:
	//!<   - 0: IKM/OKM are in keystore.
	//!<   - 1: IKM/OKM are in user memory.
	op_key_derivation_key_store_args_t *key_store_args;
	//!< Pointer to the key store arguments structure.
	//!< It must be NULL in plaintext mode.
	op_key_derivation_algo_hkdf_args_t *key_derivation_algo_args;
	//!< Pointer to the key derivation algorithm arguments structure.
	//!< The structure format is dependent on the algorithm being used.
	uint32_t key_store_args_size;
	//!< Size of the argument structure for the key store in bytes.
	//!< It must be 0x0 in plaintext mode.
	uint32_t key_derivation_algo_args_size;
	//!< Size of the argument structure for the key derivation algorithm in bytes.
	uint32_t derived_key_id;
	//!< The Key ID of the derived key when using key store arguments.
	//!< It will be 0x0 in plaintext mode.
} op_key_derivation_args_t;

/**
 * This command is used to perform the Key Derivation operation.
 *
 * It can take the IKM from the keystore or in plaintext.
 *   - For plaintext operations, the input and output are in user memory.
 *   - For key store based operations, the input and output are in key store.
 *     In this case, both input and output must be volatile key types.
 *
 * In case of Opaque operation i.e. using key store contents, the key derivation
 * command is only accepted after having opened a valid key management service.
 *
 * \param key_management_hdl handle identifying the key store management service
 * flow in case of opaque key operation. For plaintext mode, key management service
 * flow is not required, SE lib service handle can be used instead.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_key_derivation(hsm_hdl_t key_management_hdl,
			     op_key_derivation_args_t *args);
/** @} end of Key Derivation flow */
#endif
#endif
