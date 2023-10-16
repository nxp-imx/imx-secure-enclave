// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_KEY_EXCHANGE_H
#define HSM_KEY_EXCHANGE_H

#include "internal/hsm_key.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_key_generate.h"

/**
 *  @defgroup group20 Key exchange
 * @{
 */

#ifdef PSA_COMPLIANT
/**
 * Bitmap specifying the key exchange operation properties
 */
typedef uint16_t hsm_op_key_exchange_flags_t;

/**
 * Enum describing Key Exchange algorithms supported
 */
typedef enum {
	//!< ECDH HKDF SHA256
	HSM_KEY_EXCHANGE_ECDH_HKDF_SHA256 = 0x09020109,
	//!< ECDH HKDF SHA384
	HSM_KEY_EXCHANGE_ECDH_HKDF_SHA384 = 0x0902010A,
} hsm_op_key_exchange_algo_t;

/**
 * Enum describing Key Derivation algorithms supported
 */
typedef enum {
	//!< HKDF SHA256 (HMAC two-step)
	HSM_KEY_DERIVATION_HKDF_SHA256 = 0x08000109,
	//!< HKDF SHA384 (HMAC two-step)
	HSM_KEY_DERIVATION_HKDF_SHA384 = 0x0800010A,
} hsm_op_key_derivation_algo_t;

#else
/**
 * Bitmap specifying the KDF algorithm
 */
typedef uint8_t hsm_kdf_algo_id_t;

/**
 * Bitmap specifying the key exchange scheme
 */
typedef uint8_t hsm_key_exchange_scheme_id_t;

/**
 * Bitmap specifying the key exchange operation properties
 */
typedef uint8_t hsm_op_key_exchange_flags_t;
#endif

/**
 * Structure describing the key exchange operation member arguments
 */
typedef struct {
#ifdef PSA_COMPLIANT
	uint32_t signed_content_sz;
	//!< Input signed content payload size in bytes
	uint8_t *signed_content;
	//!< Input signed content payload buffer
	uint32_t peer_pubkey_sz;
	//!< Input peer public key size in bytes
	uint8_t *peer_pubkey;
	//!< Input peer public key buffer
	uint32_t user_fixed_info_sz;
	//!< Input user fixed info size in bytes
	uint8_t *user_fixed_info;
	//!< Input user fixed info buffer (optional i.e. can be NULL)
	uint32_t out_derived_key_id;
	//!< Identifier of the derived key, with FW Resp
	uint32_t out_salt_sz;
	//!< salt size in bytes, from FW Resp. It is equal to the hash
	//!< (in bytes) of hash algorithm used in the key exchange algorithm.
#else
	uint32_t key_identifier;
	//!< Identifier of the key used for derivation.
	//!< It must be zero, if HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL is set.
	uint8_t *shared_key_identifier_array;
	//!< pointer to the identifiers of the derived keys. In case of create
	//!< operation the new destination key identifiers will be stored in this
	//!< location.
	//!< In case of update operation the destination key identifiers to update
	//!< are provided by the caller in this location.
	uint8_t *ke_input;
	//!< pointer to the initiator input data related to the key exchange function.
	uint8_t *ke_output;
	//!< pointer to the output area where the data related to the key
	//!< exchange function must be written.
	//!< It corresponds to the receiver public data.
	uint8_t *kdf_input;
	//!< pointer to the input data of the KDF.
	uint8_t *kdf_output;
	//!< pointer to the output area where the non sensitive output data
	//!< related to the KDF are written.
	hsm_key_group_t shared_key_group;
	//!< It specifies the group where the derived keys will be stored.
	//!< It must be a value in the range 0-1023.
	//!< Keys belonging to the same group can be cached in the HSM local
	//!< memory through the hsm_manage_key_group API
	hsm_key_info_t shared_key_info;
	//!< bitmap specifying the properties of the derived keys, it will be
	//!< applied to all the derived keys.
	hsm_key_type_t shared_key_type;
	//!< indicates the type of the derived key.
	hsm_key_type_t initiator_public_data_type;
	//!< Indicates the public data type specified by the initiator,
	//!< e.g. public key type.
	hsm_key_exchange_scheme_id_t key_exchange_scheme;
	//!< indicates the key exchange scheme
	hsm_kdf_algo_id_t kdf_algorithm;
	//!< indicates the KDF algorithm
	uint16_t ke_input_size;
	//!< length in bytes of the input data of the key exchange function.
	uint16_t ke_output_size;
	//!< length in bytes of the output data of the key exchange function
	uint8_t shared_key_identifier_array_size;
	//!< length in byte of the area containing the shared key identifiers
	uint8_t kdf_input_size;
	//!< length in bytes of the input data of the KDF.
	uint8_t kdf_output_size;
	//!< length in bytes of the non sensitive output data related to the KDF.
	uint8_t *signed_message;
	//!< pointer to the signed_message authorizing the operation.
	uint16_t signed_msg_size;
	//!< size of the signed_message authorizing the operation.
#endif
	hsm_op_key_exchange_flags_t flags;
	//!< bitmap specifying the operation properties
} op_key_exchange_args_t;

/**
 * This command is designed to compute secret keys through a key exchange
 * protocol and the use of a key derivation function. The resulting secret
 * keys are stored into the key store as new keys or as an update of existing
 * keys.\n
 * A freshly generated key or an existing key can be used as input of the
 * shared secret calculation.\n
 * User can call this function only after having opened a key management
 * service flow.\n
 *
 *
 * This API support three use cases:
 *  - Key Encryption Key generation:
 *       - shared_key_identifier_array: it must corresponds to the KEK key id.
 *       - The kdf_input must be 0
 *       - The kdf_output must be 0
 *       - The shared_key_info must have the HSM_KEY_INFO_KEK bit set.
 *         (only Key Encryption Keys can be generated).
 *       - The shared_key_type must be HSM_KEY_TYPE_AES_256
 *       - The initiator_public_data_type must be:
 *         -- HSM_KEY_TYPE_ECDSA_NIST_P256 or
 *         -- HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256 or
 *         -- HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256.
 *       - The key_exchange_scheme must be:
 *         -- HSM_KE_SCHEME_ECDH_NIST_P256 or
 *         -- HSM_KE_SCHEME_ECDH_BRAINPOOL_R1_256 or
 *         -- HSM_KE_SCHEME_ECDH_BRAINPOOL_T1_256.
 *       - The kdf_algorithm must be HSM_KDF_ONE_STEP_SHA_256.
 *         As per as per SP800-56C rev2, the KEK is generated using the formula:
 *          => SHA_256(counter || Z || FixedInput), where:
 *          -- counter is the value 1 expressed in 32 bit and in big endian format
 *          -- Z is the shared secret generated by the DH key-establishment scheme
 *          -- FixedInput is the literal 'NXP HSM USER KEY DERIVATION'
 *             (27 bytes, no null termination).
 *       - The kdf_input_size must be 0.
 *       - The kdf_output_size must be 0.
 *       - Flags: Use of the flag HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL,
 *         is mandatory.
 *         (Only freshly generated keys can be used as input of the Z derivation.)
 *       - signed_message: mandatory in OEM CLOSED life cycle.
 *
 *  - TLS Key generation:
 *       - Only an ephemeral key pair is supported as input of the TLS
 *         key_exchange negotiation. This can be:
 *          - either a TRANSIENT private key already stored into the key store.
 *            -- Indicated by its key identifier.
 *            -- To prevent any misuse non-transient key will be rejected.
 *            -- Additionally the private key will be deleted from the key store
 *               as part of this command handling.
 *          - either a key pair freshly generated by the use of flag:
 *            -- HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL.
 *       - shared_key_identifier_array: It must correspond to the concatenation of:
 *         -- client_write_MAC_key id (4 bytes, if any),
 *         -- server_write_MAC_key id (4 bytes, if any),
 *         -- client_write_key id (4 bytes),
 *         -- the server_write_key id (4 bytes), and
 *         -- the master_secret key id (4 bytes).
 *       - The kdf_input format depends on the HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS flag:
 *          - for HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS not set, the kdf_input
 *            must correspond to the concatenation of:
 *            -- clientHello_random (32 bytes),
 *            -- serverHello_random (32 bytes),
 *            -- server_random (32 bytes) and
 *            -- client_random (32 bytes).
 *          - for HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS set, the kdf_input
 *            must correspond to the concatentation of:
 *            -- message_hash,
 *            -- server_random (32 bytes) and
 *            -- client_random (32 bytes).
 *            The length of the message_hash must be:
 *            -- 32 bytes for SHA256 based KDFs, or
 *            -- 48 bytes for SHA384 based KDFs.
 *       - kdf_output: the concatenation of:
 *         -- client_write_iv (4 bytes) and
 *         -- server_write_iv (4 bytes)
 *         will be stored at this address.
 *       - The shared_key_info must have:
 *         -- the HSM_KEY_INFO_TRANSIENT bit set (only transient keys can be generated),
 *         -- the HSM_KEY_INFO_KEK bit is not allowed.
 *       - The shared_key_type is not applicable and must be left to 0.
 *       - The initiator_public_data_type must be:
 *         -- HSM_KEY_TYPE_ECDSA_NIST_P256/384, or
 *         -- HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256/384.
 *       - The key_exchange_scheme must be:
 *         -- HSM_KE_SCHEME_ECDH_NIST_P256/384, or
 *         -- HSM_KE_SCHEME_ECDH_BRAINPOOL_R1_256/384.
 *       - The kdf_algorithm must be HSM_KDF_HMAC_SHA_xxx_TLS_xxx.
 *         -- The generated MAC keys will have type ALG_HMAC_XXX, where,
 *            --- XXX corresponds to the key length in bit of generated MAC key.
 *         -- The generated encryption keys will have type HSM_KEY_TYPE_AES_XXX, where,
 *            --- XXX corresponds to the key length in bit of the generated AES key.
 *         -- The master_secret key can only be used for:
 *            --- the hsm_tls_finish function, or
 *            --- be deleted using the hsm_manage_key function.
 *       - kdf_input_size:
 *          - for HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS not set, it must be 128 bytes.
 *          - for HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS set, it must be:
 *            -- 96 (SHA256), or
 *            -- 112 (SHA384) bytes.
 *       - kdf_output_size: It must be 8 bytes
 *       - signed_message: it must be NULL
 *
 *  - SM2 key generation (as specified in GB/T 32918):
 *       - Only the receiver role is supported.
 *       - ke_input = (x||y) || (xephemeral||yephemeral) of the 2 public keys of initiator
 *       - ke_out = (x||y)|| (xephemeral||yephemeral) of the 2 public keys the receiver
 *       - kdf_input = (Zinitiator||Zinitiator||V1) if:
 *         -- HSM_OP_KEY_EXCHANGE_FLAGS_KEY_CONF_EN enabled. Where,
 *            V1 is the verification value calculated on the initiator side.
 *       - kdf_output =
 *         -- (VA||VB), if HSM_OP_KEY_EXCHANGE_FLAGS_KEY_CONF_EN enabled,
 *         -- 0 otherwise.
 *       - shared_key_info: the HSM_KEY_INFO_KEK bit is not allowed.
 *       - The shared_key_type must be HSM_KEY_TYPE_SM4_128 or HSM_KEY_TYPE_DSA_SM2_FP_256
 *       - The initiator_public_data_type must be HSM_KEY_TYPE_DSA_SM2_FP_256
 *       - The key_exchange_scheme must be HSM_KE_SCHEME_SM2_FP_256.
 *       - The kdf_algorithm must be HSM_KDF_ALG_FOR_SM2.
 *       - Flags: the HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL flag is not supported
 *       - signed_message: it must be NULL
 *
 * \param key_management_hdl handle identifying the key store management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_key_exchange(hsm_hdl_t key_management_hdl,
			   op_key_exchange_args_t *args);

#ifndef PSA_COMPLIANT
#define HSM_KDF_ALG_FOR_SM2 \
	((hsm_kdf_algo_id_t)0x10u)
//!< SM2 Key exchange KDF algorithm

#define HSM_KDF_HMAC_SHA_256_TLS_0_16_4 \
	((hsm_kdf_algo_id_t)0x20u)
//!< TLS PRF based on HMAC with SHA-256, the resulting mac_key_length is 0 bytes,
//!< enc_key_length is 16 bytes and fixed_iv_length is 4 bytes.

#define HSM_KDF_HMAC_SHA_384_TLS_0_32_4 \
	((hsm_kdf_algo_id_t)0x21u)
//!< TLS PRF based on HMAC with SHA-384, the resulting mac_key_length is 0 bytes,
//!< enc_key_length is 32 bytes and fixed_iv_length is 4 bytes.

#define HSM_KDF_HMAC_SHA_256_TLS_0_32_4 \
	((hsm_kdf_algo_id_t)0x22u)
//!< TLS PRF based on HMAC with SHA-256, the resulting mac_key_length is 0 bytes,
//!< enc_key_length is 32 bytes and fixed_iv_length is 4 bytes.

#define HSM_KDF_HMAC_SHA_256_TLS_32_16_4 \
	((hsm_kdf_algo_id_t)0x23u)
//!< TLS PRF based on HMAC with SHA-256, the resulting mac_key_length is 32 bytes,
//!< enc_key_length is 16 bytes and fixed_iv_length is 4 bytes.

#define HSM_KDF_HMAC_SHA_384_TLS_48_32_4 \
	((hsm_kdf_algo_id_t)0x24u)
//!< TLS PRF based on HMAC with SHA-384, the resulting mac_key_length is 48 bytes,
//!< enc_key_length is 32 bytes and fixed_iv_length is 4 bytes.

#define HSM_KDF_ONE_STEP_SHA_256 \
	((hsm_kdf_algo_id_t)0x31u)
//!< One-Step Key Derivation using SHA256 as per NIST SP80056C. It can only be used,
//!< together with a signed message, to generate KEKs (key encryption keys) for
//!< key injection (hsm_manage_key API).

#define HSM_KE_SCHEME_ECDH_NIST_P256 \
	((hsm_key_exchange_scheme_id_t)0x02u)
//!< Key exchange scheme ECDH_NIST_P256

#define HSM_KE_SCHEME_ECDH_NIST_P384 \
	((hsm_key_exchange_scheme_id_t)0x03u)
//!< Key exchange scheme ECDH_NIST_P384

#define HSM_KE_SCHEME_ECDH_BRAINPOOL_R1_256 \
	((hsm_key_exchange_scheme_id_t)0x13u)
//!< Key exchange scheme ECDH_BRAINPOOL_R1_256

#define HSM_KE_SCHEME_ECDH_BRAINPOOL_R1_384 \
	((hsm_key_exchange_scheme_id_t)0x15u)
//!< Key exchange scheme ECDH_BRAINPOOL_R1_384

#define HSM_KE_SCHEME_ECDH_BRAINPOOL_T1_256 \
	((hsm_key_exchange_scheme_id_t)0x23u)
//!< Key exchange scheme ECDH_BRAINPOOL_T1_256

#define HSM_KE_SCHEME_SM2_FP_256 \
	((hsm_key_exchange_scheme_id_t)0x42u)
//!< Key exchange scheme SM2_FP_256

#define HSM_OP_KEY_EXCHANGE_FLAGS_UPDATE \
	((hsm_op_key_exchange_flags_t)(1u << 0))
//!< User can replace an existing key only by the derived key which should have
//!< the same type of the original one.

#define HSM_OP_KEY_EXCHANGE_FLAGS_CREATE \
	((hsm_op_key_exchange_flags_t)(1u << 1))
//!< Create a new key

#define HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL \
	((hsm_op_key_exchange_flags_t)(1u << 2))
//!< Use an ephemeral key (freshly generated key)

#define HSM_OP_KEY_EXCHANGE_FLAGS_KEY_CONF_EN \
	((hsm_op_key_exchange_flags_t)(1u << 3))
//!< Enable key confirmation (valid only in case of HSM_KE_SCHEME_SM2_FP_256)

#define HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS  \
	((hsm_op_key_exchange_flags_t)(1u << 4))
//!< Use extended master secret for TLS KDFs
#else
//!< Use zeros salt
#define HSM_OP_KEY_EXCHANGE_FLAGS_SALT_ZERO \
	((hsm_op_key_exchange_flags_t)(0u << 0))
//!< Use peer public key hash salt
#define HSM_OP_KEY_EXCHANGE_FLAGS_SALT_PEER_PUBKEY_HASH \
	((hsm_op_key_exchange_flags_t)(1u << 0))
//!< Use peer public key hash salt
#define HSM_OP_KEY_EXCHANGE_FLAGS_MONOTONIC \
	((hsm_op_key_exchange_flags_t)(1u << 5))
//!< When used in conjunction with STRICT flag, the request is completed only when
//!< the monotonic counter has been updated.
#endif
#define HSM_OP_KEY_EXCHANGE_FLAGS_STRICT_OPERATION \
	((hsm_op_key_exchange_flags_t)(1u << 7))
//!< The request is completed only when the new key has been written in the NVM.
//!< This applicable for persistent key only.
//!< NOTE: In latest ELE FW API guide, STRICT has been replaced with SYNC.

/**
 *\addtogroup qxp_specific
 * \ref group20
 *
 * - \ref HSM_KDF_HMAC_SHA_256_TLS_0_16_4 is not supported.
 * - \ref HSM_KDF_HMAC_SHA_384_TLS_0_32_4 is not supported.
 * - \ref HSM_KDF_HMAC_SHA_256_TLS_0_32_4 is not supported.
 * - \ref HSM_KDF_HMAC_SHA_256_TLS_32_16_4 is not supported.
 * - \ref HSM_KDF_HMAC_SHA_384_TLS_48_32_4 is not supported.
 * - \ref HSM_KE_SCHEME_ECDH_BRAINPOOL_T1_256 is not supported.
 */
/**
 *\addtogroup dxl_specific
 * \ref group20
 *
 * - \ref HSM_KDF_HMAC_SHA_256_TLS_0_16_4 is not supported.
 * - \ref HSM_KDF_HMAC_SHA_384_TLS_0_32_4 is not supported.
 * - \ref HSM_KDF_HMAC_SHA_256_TLS_0_32_4 is not supported.
 * - \ref HSM_KDF_HMAC_SHA_256_TLS_32_16_4 is not supported.
 * - \ref HSM_KDF_HMAC_SHA_384_TLS_48_32_4 is not supported.
 */
/** @} end of key exchange operation */
#endif
