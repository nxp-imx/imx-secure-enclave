// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_API2_H
#define HSM_API2_H

#ifndef PSA_COMPLIANT
#include <stdint.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_key.h"
#include "internal/hsm_utils.h"

typedef uint8_t hsm_op_manage_key_group_flags_t;
typedef struct {
	//!< it must be a value in the range 0-1023.
	//Keys belonging to the same group can be cached in the HSM local memory
	//through the hsm_manage_key_group API.
	hsm_key_group_t key_group;
	//!< bitmap specifying the operation properties.
	hsm_op_manage_key_group_flags_t flags;
	uint8_t reserved;
} op_manage_key_group_args_t;

/**
 * This command is designed to perform the following operations:
 *  - lock/unlock down a key group in the HSM local memory so that the keys are
 *    available to the HSM without additional latency
 *  - un-lock a key group. HSM may export the key group into the external NVM to
 *    free up local memory as needed
 *  - delete an existing key group
 *
 * User can call this function only after having opened a key management service
 * flow.
 *
 * \param key_management_hdl handle identifying the key management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_manage_key_group(hsm_hdl_t key_management_hdl,
			       op_manage_key_group_args_t *args);

//!< The entire key group will be cached in the HSM local memory.
#define HSM_OP_MANAGE_KEY_GROUP_FLAGS_CACHE_LOCKDOWN \
	((hsm_op_manage_key_group_flags_t)(1u << 0))

//!< HSM may export the key group in the external NVM to free up the local
//	 memory. HSM will copy the key group in the local memory again in case
//	 of key group usage/update.
#define HSM_OP_MANAGE_KEY_GROUP_FLAGS_CACHE_UNLOCK \
	((hsm_op_manage_key_group_flags_t)(1u << 1))

#ifdef PSA_COMPLIANT
//!< Import the key group.
#define HSM_OP_MANAGE_KEY_GROUP_FLAGS_IMPORT \
	((hsm_op_manage_key_group_flags_t)(1u << 2))

//!< Export the key group.
#define HSM_OP_MANAGE_KEY_GROUP_FLAGS_EXPORT \
	((hsm_op_manage_key_group_flags_t)(1u << 3))
#else
//!< Delete an existing key group.
#define HSM_OP_MANAGE_KEY_GROUP_FLAGS_DELETE \
	((hsm_op_manage_key_group_flags_t)(1u << 2))
#endif

//!< The request is completed only when the update has been written in the NVM.
//	 Not applicable for cache lockdown/unlock.
#define HSM_OP_MANAGE_KEY_GROUP_FLAGS_STRICT_OPERATION \
	((hsm_op_manage_key_group_flags_t)(1u << 7))

typedef uint8_t hsm_op_but_key_exp_flags_t;
typedef struct {
	//!< identifier of the key to be expanded.
	uint32_t key_identifier;
	//!< pointer to the expansion function value input
	uint8_t *expansion_function_value;
	//!< pointer to the hash value input.\n In case of explicit certificate,
	//the hash value address must be set to 0.
	uint8_t *hash_value;
	//!< pointer to the private reconstruction value input.
	//In case of explicit certificate, the pr_reconstruction_value address
	//must be set to 0.
	uint8_t *pr_reconstruction_value;
	//!< length in bytes of the expansion function input
	uint8_t expansion_function_value_size;
	//!< length in bytes of the hash value input.
	//In case of explicit certificate, the hash_value_size parameter must
	//be set to 0.
	uint8_t hash_value_size;
	//!< length in bytes of the private reconstruction value input.
	//In case of explicit certificate, the pr_reconstruction_value_size
	//parameter must be set to 0.
	uint8_t pr_reconstruction_value_size;
	//!< bitmap specifying the operation properties
	hsm_op_but_key_exp_flags_t flags;
	//!< pointer to identifier of the derived key to be used for the operation.
	//In case of create operation the new destination key identifier will be
	//stored in this location.
	uint32_t *dest_key_identifier;
	//!< pointer to the output area where the public key must be written.
	uint8_t *output;
	//!< length in bytes of the generated key, if the size is 0, no key is
	//copied in the output.
	uint16_t output_size;
	//!< indicates the type of the key to be derived.
	hsm_key_type_t key_type;
	uint8_t reserved;
	//!< it must be a value in the range 0-1023. Keys belonging to the same
	//group can be cached in the HSM local memory through the
	//hsm_manage_key_group API
	hsm_key_group_t key_group;
	//!< bitmap specifying the properties of the derived key.
	hsm_key_info_t key_info;
} op_butt_key_exp_args_t;

/**
 * This command is designed to perform the butterfly key expansion operation on
 * an ECC private key in case of implicit and explicit certificates. Optionally
 * the resulting public key is exported.
 * The result of the key expansion function f_k is calculated outside the HSM
 * and passed as input. The expansion function is defined as f_k = f_k_int mod l,
 * where l is the order of the group of points on the curve.\n
 * User can call this function only after having opened a key management service flow.
 *
 * Explicit certificates:
 *  - f_k = expansion function value
 *
 * out_key = Key  + f_k
 * \n\n
 *
 * Implicit certificates:
 *  - f_k = expansion function value,
 *  - hash = hash value used in the derivation of the pseudonym ECC key,
 *  - pr_v = private reconstruction value
 *
 * out_key = (Key  + f_k)*hash + pr_v
 *
 * \param key_management_hdl handle identifying the key store management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_butterfly_key_expansion(hsm_hdl_t key_management_hdl,
				      op_butt_key_exp_args_t *args);

//!< User can replace an existing key only by generating a key with the same
//type of the original one.
#define HSM_OP_BUTTERFLY_KEY_FLAGS_UPDATE \
	((hsm_op_but_key_exp_flags_t)(1u << 0))

//!< Create a new key.
#define HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE \
	((hsm_op_but_key_exp_flags_t)(1u << 1))

//!< butterfly key expansion using implicit certificate.
#define HSM_OP_BUTTERFLY_KEY_FLAGS_IMPLICIT_CERTIF \
	((hsm_op_but_key_exp_flags_t)(0u << 2))

//!< butterfly key expansion using explicit certificate.
#define HSM_OP_BUTTERFLY_KEY_FLAGS_EXPLICIT_CERTIF \
	((hsm_op_but_key_exp_flags_t)(1u << 2))

//!< The request is completed only when the new key has been written in the NVM.
#define HSM_OP_BUTTERFLY_KEY_FLAGS_STRICT_OPERATION \
	((hsm_op_but_key_exp_flags_t)(1u << 7))

/**
 *\addtogroup qxp_specific
 * \ref group3
 *
 * - \ref HSM_OP_MANAGE_KEY_GROUP_FLAGS_DELETE is not supported.
 *
 * - \ref HSM_KEY_TYPE_ECDSA_NIST_P521 is not supported.
 * - \ref HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_320 is not supported.
 * - \ref HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_512 is not supported.
 * - \ref HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256 is not supported.
 * - \ref HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_320 is not supported.
 * - \ref HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384 is not supported.
 * - \ref HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_512 is not supported.
 * - \ref HSM_KEY_TYPE_DSA_SM2_FP_256 is not supported.
 * - \ref HSM_KEY_TYPE_SM4_128 is not supported.
 * - \ref HSM_KEY_TYPE_HMAC_224 is not supported.
 * - \ref HSM_KEY_TYPE_HMAC_256 is not supported.
 * - \ref HSM_KEY_TYPE_HMAC_384 is not supported.
 * - \ref HSM_KEY_TYPE_HMAC_512 is not supported.
 *
 * - \ref hsm_butterfly_key_expansion: This feature is disabled when part is
 *        running in FIPS approved mode. Any call to this API will results in a
 *        HSM_FEATURE_DISABLED error.
 * - \ref hsm_key_type_t of op_butt_key_exp_args_t: Only following are supported:
 *        HSM_KEY_TYPE_ECDSA_NIST_P256, and
 *        HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256
 */

/**
 *\addtogroup dxl_specific
 * \ref group3
 *
 * - \ref HSM_OP_MANAGE_KEY_GROUP_FLAGS_DELETE is not supported.
 *
 * - \ref HSM_KEY_TYPE_HMAC_224 is not supported.
 * - \ref HSM_KEY_TYPE_HMAC_256 is not supported.
 * - \ref HSM_KEY_TYPE_HMAC_384 is not supported.
 * - \ref HSM_KEY_TYPE_HMAC_512 is not supported.
 *
 * - \ref hsm_key_type_t of op_butt_key_exp_args_t: Only following are supported:
 *   HSM_KEY_TYPE_ECDSA_NIST_P256,
 *   HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256 and
 *   HSM_KEY_TYPE_DSA_SM2_FP_256 are supported.
 *
 */
/** @} end of key management service flow */

typedef uint8_t hsm_op_ecies_dec_flags_t;
typedef struct {
	//!< identifier of the private key to be used for the operation
	uint32_t key_identifier;
	//!< pointer to the VCT input
	uint8_t *input;
	//!< pointer to the KDF P1 input parameter
	uint8_t *p1;
	//!< pointer to the MAC P2 input parameter should be NULL
	uint8_t *p2;
	//!< pointer to the output area where the plaintext must be written
	uint8_t *output;
	//!< length in bytes of the input VCT should be equal to 96 bytes
	uint32_t input_size;
	//!< length in bytes of the output plaintext should be equal to 16 bytes
	uint32_t output_size;
	//!< length in bytes of the KDF P1 parameter should be equal to 32 bytes
	uint16_t p1_size;
	//!< length in bytes of the MAC P2 parameter should be zero reserved for
	//   generic use cases
	uint16_t p2_size;
	//!< length in bytes of the requested message authentication code should
	//   be equal to 16 bytes
	uint16_t mac_size;
	//!< indicates the type of the used key
	hsm_key_type_t key_type;
	//!< bitmap specifying the operation attributes.
	hsm_op_ecies_dec_flags_t flags;
} op_ecies_dec_args_t;

/**
 * Decrypt data usign ECIES \n
 * User can call this function only after having opened a cipher  store service flow.\n
 * ECIES is supported with the constraints specified in 1609.2-2016.
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_ecies_decryption(hsm_hdl_t cipher_hdl, op_ecies_dec_args_t *args);

typedef uint8_t hsm_op_import_public_key_flags_t;
typedef struct {
	//!< pointer to the public key to be imported
	uint8_t *key;
	//!< length in bytes of the input key
	uint16_t key_size;
	//!< indicates the type of the key to be imported.
	hsm_key_type_t key_type;
	//!< bitmap specifying the operation attributes
	hsm_op_import_public_key_flags_t flags;
} op_import_public_key_args_t;

/**
 * Import a public key to be used for several verification operations, a
 * reference to the imported key is returned.
 *
 * User can use the returned reference in the hsm_verify_signature API by
 * setting the HSM_OP_VERIFY_SIGN_FLAGS_KEY_INTERNAL flag.
 *
 * Only not-compressed keys (x,y) can be imported by this command.
 * Compressed keys can be decompressed by using the dedicated API.
 *
 * User can call this function only after having opened a signature
 * verification service flow.
 *
 * \param signature_ver_hdl handle identifying the signature verification service flow.
 * \param args pointer to the structure containing the function arguments.
 * \param key_ref pointer to where the 4 bytes key reference to be used as
 *        key in the hsm_verify_signature will be stored.
 *
 * \return error code
 */
hsm_err_t hsm_import_public_key(hsm_hdl_t signature_ver_hdl,
				op_import_public_key_args_t *args,
				uint32_t *key_ref);

/**
 *  @defgroup group9 Public key reconstruction
 * @{
 */
typedef uint8_t hsm_op_pub_key_rec_flags_t;
typedef struct {
	//!< pointer to the public reconstruction value extracted from the
	//   implicit certificate.
	uint8_t *pub_rec;
	//!< pointer to the input hash value. In the butterfly scheme it
	//   corresponds to the hash value calculated over PCA certificate and,
	//   concatenated, the implicit certificat.
	uint8_t *hash;
	//!< pointer to the CA public key
	uint8_t *ca_key;
	//!< pointer to the output area where the reconstructed public key must
	//   be written.
	uint8_t *out_key;
	//!< length in bytes of the public reconstruction value
	uint16_t pub_rec_size;
	//!< length in bytes of the input hash
	uint16_t hash_size;
	//!< length in bytes of the input CA public key
	uint16_t ca_key_size;
	//!< length in bytes of the output key
	uint16_t out_key_size;
	//!< indicates the type of the managed key.
	hsm_key_type_t key_type;
	//!< flags bitmap specifying the operation attributes.
	hsm_op_pub_key_rec_flags_t flags;
	uint16_t reserved;
} op_pub_key_rec_args_t;

/**
 * Reconstruct an ECC public key provided by an implicit certificate\n
 * User can call this function only after having opened a session\n
 * This API implements the following formula:\n
 * out_key = (pub_rec * hash) + ca_key
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_pub_key_reconstruction(hsm_hdl_t session_hdl,
				     op_pub_key_rec_args_t *args);

/**
 *\addtogroup qxp_specific
 * \ref group9
 *
 * - \ref This feature is disabled when part is running in FIPS approved mode.
 *        Any call to this API will results in a HSM_FEATURE_DISABLED error.
 * - \ref hsm_key_type_t of op_pub_key_rec_args_t: Only following are supported:
 *        HSM_KEY_TYPE_ECDSA_NIST_P256, and
 *        HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256
 */
/**
 *\addtogroup dxl_specific
 * \ref group9
 *
 * - \ref hsm_key_type_t of op_pub_key_rec_args_t: Only following are supported:
 *        HSM_KEY_TYPE_ECDSA_NIST_P256,
 *        HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256, and
 *        HSM_KEY_TYPE_DSA_SM2_FP_256
 *
 */
/** @} end of public key reconstruction operation */

/**
 *  @defgroup group10 Public key decompression
 * @{
 */
typedef uint8_t hsm_op_pub_key_dec_flags_t;
typedef struct {
	//!< pointer to the compressed ECC public key.
	//   The expected key format is x||lsb_y where lsb_y is 1 byte having value:
	//   1 if least-significant bit of original (uncompressed) y coordinate is set.
	//   0 otherwise.
	uint8_t *key;
	//!< pointer to the output area where the decompressed public key must be written.
	uint8_t *out_key;
	//!< length in bytes of the input compressed public key
	uint16_t key_size;
	//!< length in bytes of the resulting public key
	uint16_t out_key_size;
	//!< indicates the type of the manged keys.
	hsm_key_type_t key_type;
	//!< bitmap specifying the operation attributes.
	hsm_op_pub_key_dec_flags_t flags;
	uint16_t reserved;
} op_pub_key_dec_args_t;

/**
 * Decompress an ECC public key \n
 * The expected key format is x||lsb_y where lsb_y is 1 byte having value:
 *  1 if the least-significant bit of the original (uncompressed) y coordinate is set.
 *  0 otherwise.
 * User can call this function only after having opened a session
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_pub_key_decompression(hsm_hdl_t session_hdl,
				    op_pub_key_dec_args_t *args);

/**
 *\addtogroup qxp_specific
 * \ref group10
 *
 * - \ref This feature is disabled when part is running in FIPS approved mode.
 *        Any call to this API will results in a HSM_FEATURE_DISABLED error.
 */
/** @} end of public key decompression operation */

/**
 *  @defgroup group11 ECIES encryption
 * @{
 */
typedef uint8_t hsm_op_ecies_enc_flags_t;
typedef struct {
	//!< pointer to the input plaintext
	uint8_t *input;
	//!< pointer to the input recipient public key
	uint8_t *pub_key;
	//!< pointer to the KDF P1 input parameter
	uint8_t *p1;
	//!< pointer to the MAC P2 input parameter should be NULL
	uint8_t *p2;
	//!< pointer to the output area where the VCT must be written
	uint8_t *output;
	//!< length in bytes of the input plaintext should be equal to 16 bytes
	uint32_t input_size;
	//!< length in bytes of the KDF P1 parameter should be equal to 32 bytes
	uint16_t p1_size;
	//!< length in bytes of the MAC P2 parameter should be zero reserved for
	//   generic use cases
	uint16_t p2_size;
	//!< length in bytes of the recipient public key should be equal to 64 bytes
	uint16_t pub_key_size;
	//!< length in bytes of the requested message authentication code should
	//   be equal to 16 bytes
	uint16_t mac_size;
	//!< length in bytes of the output VCT should be equal to 96 bytes
	uint32_t out_size;
	//!< indicates the type of the recipient public key
	hsm_key_type_t key_type;
	//!< bitmap specifying the operation attributes.
	hsm_op_ecies_enc_flags_t flags;
	uint16_t reserved;
} op_ecies_enc_args_t;

/**
 * Encrypt data usign ECIES \n
 * User can call this function only after having opened a session.\n
 * ECIES is supported with the constraints specified in 1609.2-2016.
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_ecies_encryption(hsm_hdl_t session_hdl, op_ecies_enc_args_t *args);

/**
 *\addtogroup qxp_specific
 * \ref group11
 *
 * - \ref hsm_ecies_encryption: This feature is disabled when part is running in
 *        FIPS approved mode. Any call to this API will results in a
 *        HSM_FEATURE_DISABLED error.
 * - \ref hsm_key_type_t of op_ecies_enc_args_t: Only followinga are supported:
 *        HSM_KEY_TYPE_ECDSA_NIST_P256, and
 *        HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256.
 *
 */

/**
 *\addtogroup dxl_specific
 * \ref group11
 *
 * - \ref hsm_key_type_t of op_ecies_enc_args_t: Only following are supported:
 *        HSM_KEY_TYPE_ECDSA_NIST_P256, and
 *        HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256.
 *
 */
/** @} end of ECIES encryption operation */
/**
 *  @defgroup group14 Root KEK export
 * @{
 */
typedef uint8_t hsm_op_export_root_kek_flags_t;
typedef struct {
	//!< pointer to signed_message authorizing the operation
	uint8_t *signed_message;
	//!< pointer to the output area where the derived root kek
	//   (key encryption key) must be written
	uint8_t *out_root_kek;
	//!< size of the signed_message authorizing the operation
	uint16_t signed_msg_size;
	//!< length in bytes of the root kek. Must be 32 bytes.
	uint8_t root_kek_size;
	//!< flags bitmap specifying the operation attributes.
	hsm_op_export_root_kek_flags_t flags;
	uint8_t reserved[2];
} op_export_root_kek_args_t;

/**
 * Export the root key encryption key. This key is derived on chip.
 * It can be common or chip unique.
 * This key will be used to import key in the key store through the manage key API.
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_export_root_key_encryption_key(hsm_hdl_t session_hdl,
					     op_export_root_kek_args_t *args);
#define HSM_OP_EXPORT_ROOT_KEK_FLAGS_COMMON_KEK \
		((hsm_op_export_root_kek_flags_t)(1u << 0))
#define HSM_OP_EXPORT_ROOT_KEK_FLAGS_UNIQUE_KEK \
		((hsm_op_export_root_kek_flags_t)(0u << 0))
/** @} end of export root key encryption key operation */

/**
 *  @defgroup group17 SM2 Get Z
 * @{
 */
typedef uint8_t hsm_op_sm2_get_z_flags_t;
typedef struct {
	//!< pointer to the sender public key
	uint8_t *public_key;
	//!< pointer to the sender identifier
	uint8_t *identifier;
	//!< pointer to the output area where the Z value must be written
	uint8_t *z_value;
	//!< length in bytes of the sender public key should be equal to 64 bytes
	uint16_t public_key_size;
	//!< length in bytes of the identifier
	uint8_t id_size;
	//!< length in bytes of Z should be at least 32 bytes
	uint8_t z_size;
	//!< indicates the type of the sender public key.
	//   Only HSM_KEY_TYPE_DSA_SM2_FP_256 is supported.
	hsm_key_type_t key_type;
	//!< bitmap specifying the operation attributes.
	hsm_op_sm2_get_z_flags_t flags;
	uint8_t reserved[2];
} op_sm2_get_z_args_t;

/**
 * This command is designed to compute:
 *  Z = SM3(Entl || ID || a || b || xG || yG || xpubk || ypubk)
 *  where,
 *  - ID, Entl: user distinguishing identifier and length,
 *  - a, b, xG and yG : curve parameters,
 *  - xpubk , ypubk : public key \n\n
 * This value is used for SM2 public key cryptography algorithms, as specified in GB/T 32918.
 * User can call this function only after having opened a session.\n
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_sm2_get_z(hsm_hdl_t session_hdl, op_sm2_get_z_args_t *args);

/**
 *\addtogroup qxp_specific
 * \ref group17
 *
 * - \ref This API is not supported.
 *
 */
/** @} end of SM2 Get Z operation */

/**
 *  @defgroup group18 SM2 ECES decryption
 * @{
 */

typedef uint8_t hsm_svc_sm2_eces_flags_t;
typedef struct {
	//!< bitmap indicating the service flow properties
	hsm_svc_sm2_eces_flags_t flags;
	uint8_t reserved[3];
} open_svc_sm2_eces_args_t;

/**
 * Open a SM2 ECES decryption service flow\n
 * User can call this function only after having opened a key store.\n
 * User must open this service in order to perform SM2 decryption.
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 * \param sm2_eces_hdl pointer to where the sm2 eces service flow handle must be written.
 *
 * \return error code
 */
hsm_err_t hsm_open_sm2_eces_service(hsm_hdl_t key_store_hdl,
				    open_svc_sm2_eces_args_t *args,
				    hsm_hdl_t *sm2_eces_hdl);

/**
 * Terminate a previously opened SM2 ECES service flow
 *
 * \param sm2_eces_hdl handle identifying the SM2 ECES service flow to be closed.
 *
 * \return error code
 */
hsm_err_t hsm_close_sm2_eces_service(hsm_hdl_t sm2_eces_hdl);

typedef uint8_t hsm_op_sm2_eces_dec_flags_t;
typedef struct {
	//!< identifier of the private key to be used for the operation
	uint32_t key_identifier;
	//!< pointer to the input ciphertext
	uint8_t *input;
	//!< pointer to the output area where the plaintext must be written
	uint8_t *output;
	//!< length in bytes of the input ciphertext.
	uint32_t input_size;
	//!< length in bytes of the output plaintext
	uint32_t output_size;
	//!< Indicates the type of the used key.
	//   Only HSM_KEY_TYPE_DSA_SM2_FP_256 is supported.
	hsm_key_type_t key_type;
	//!< bitmap specifying the operation attributes.
	hsm_op_sm2_eces_dec_flags_t flags;
	uint16_t reserved;
} op_sm2_eces_dec_args_t;

/**
 * Decrypt data usign SM2 ECES \n
 * User can call this function only after having opened a SM2 ECES service flow.\n
 * SM2 ECES is supported with the requirements specified in the GB/T 32918.4.
 *
 * \param sm2_eces_hdl handle identifying the SM2 ECES
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_sm2_eces_decryption(hsm_hdl_t sm2_eces_hdl,
				  op_sm2_eces_dec_args_t *args);

/**
 *\addtogroup qxp_specific
 * \ref group18
 *
 * - \ref All the APIs related the SM2 ECES decryption are not supported.
 *
 */
/**
 *\addtogroup dxl_specific
 * \ref group18
 *
 * - \ref The output_size should be a multiple of 4 bytes.
 *
 */
/** @} end of SM2 ECES decryption flow */

/**
 *  @defgroup group19 SM2 ECES encryption
 * @{
 */

typedef uint8_t hsm_op_sm2_eces_enc_flags_t;
typedef struct {
	//!< pointer to the input plaintext
	uint8_t *input;
	//!< pointer to the output area where the ciphertext must be written
	uint8_t *output;
	//!< pointer to the input recipient public key
	uint8_t *pub_key;
	//!< length in bytes of the input plaintext
	uint32_t input_size;
	//!< Length in bytes of the output ciphertext.
	//   It should be at sum of:
	//   - least input_size,
	//   - 97 bytes (overhead related to C1 and C3 - as specified below), and
	//   - size alignment constraints specific to a given implementation.
	//
	//   See related chapter for more details.
	uint32_t output_size;
	//!< length in bytes of the recipient public key should be equal to 64 bytes
	uint16_t pub_key_size;
	//!< Indicates the type of the recipient public key.
	//   Only HSM_KEY_TYPE_DSA_SM2_FP_256 is supported.
	hsm_key_type_t key_type;
	//!< bitmap specifying the operation attributes.
	hsm_op_sm2_eces_enc_flags_t flags;
} op_sm2_eces_enc_args_t;

/**
 * Encrypt data usign SM2 ECES \n
 * User can call this function only after having opened a session.\n
 * SM2 ECES is supported with the requirements specified in the GB/T 32918.4. \n
 * The output (i.e. ciphertext) is stored in the format C= C1||C2||C3. Where,
 *      C1 = PC||x1||y1  where PC=04 and (x1,y1) are the coordinates of a an
 *                             elliptic curve point \n
 *      C2 = M xor t where t=KDF(x2||y2, input_size) and (x2,y2) are the
 *                             coordinates of a an elliptic curve point \n
 *      C3 = SM3 (x2||M||y2)

 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_sm2_eces_encryption(hsm_hdl_t session_hdl,
				  op_sm2_eces_enc_args_t *args);

/**
 *\addtogroup qxp_specific
 * \ref group19
 *
 * - \ref This API is not supported.
 *
 */
/**
 *\addtogroup dxl_specific
 * \ref group19
 *
 * - \ref The output_size should be a multiple of 4 bytes.
 *
 */
/** @} end of SM2 ECES encryption operation */

/**
 *  @defgroup group20 Key exchange
 * @{
 */
typedef uint8_t hsm_kdf_algo_id_t;
typedef uint8_t hsm_key_exchange_scheme_id_t;
typedef uint8_t hsm_op_key_exchange_flags_t;
typedef struct {
	//!< Identifier of the key used for derivation.
	//   It must be zero, if HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL is set.
	uint32_t key_identifier;
	//!< pointer to the identifiers of the derived keys. In case of create
	//   operation the new destination key identifiers will be stored in this location.
	//   In case of update operation the destination key identifiers to update
	//   are provided by the caller in this location.
	uint8_t *shared_key_identifier_array;
	//!< pointer to the initiator input data related to the key exchange function.
	uint8_t *ke_input;
	//!< pointer to the output area where the data related to the key
	//   exchange function must be written.
	//   It corresponds to the receiver public data.
	uint8_t *ke_output;
	//!< pointer to the input data of the KDF.
	uint8_t *kdf_input;
	//!< pointer to the output area where the non sensitive output data
	//   related to the KDF are written.
	uint8_t *kdf_output;
	//!< It specifies the group where the derived keys will be stored.
	//   It must be a value in the range 0-1023.
	//   Keys belonging to the same group can be cached in the HSM local
	//   memory through the hsm_manage_key_group API
	hsm_key_group_t shared_key_group;
	//!< bitmap specifying the properties of the derived keys, it will be
	//   applied to all the derived keys.
	hsm_key_info_t shared_key_info;
	//!< indicates the type of the derived key.
	hsm_key_type_t shared_key_type;
	//!< Indicates the public data type specified by the initiator,
	//   e.g. public key type.
	hsm_key_type_t initiator_public_data_type;
	//!< indicates the key exchange scheme
	hsm_key_exchange_scheme_id_t key_exchange_scheme;
	//!< indicates the KDF algorithm
	hsm_kdf_algo_id_t kdf_algorithm;
	//!< length in bytes of the input data of the key exchange function.
	uint16_t ke_input_size;
	//!< length in bytes of the output data of the key exchange function
	uint16_t ke_output_size;
	//!< length in byte of the area containing the shared key identifiers
	uint8_t shared_key_identifier_array_size;
	//!< length in bytes of the input data of the KDF.
	uint8_t kdf_input_size;
	//!< length in bytes of the non sensitive output data related to the KDF.
	uint8_t kdf_output_size;
	//!< bitmap specifying the operation properties
	hsm_op_key_exchange_flags_t flags;
	//!< pointer to the signed_message authorizing the operation.
	uint8_t *signed_message;
	//!< size of the signed_message authorizing the operation.
	uint16_t signed_msg_size;
	//!< It must be 0.
	uint8_t reserved[2];
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

#define HSM_KDF_ALG_FOR_SM2 \
	((hsm_kdf_algo_id_t)0x10u)

//!< TLS PRF based on HMAC with SHA-256, the resulting mac_key_length is 0 bytes,
//   enc_key_length is 16 bytes and fixed_iv_length is 4 bytes.
#define HSM_KDF_HMAC_SHA_256_TLS_0_16_4 \
	((hsm_kdf_algo_id_t)0x20u)

//!< TLS PRF based on HMAC with SHA-384, the resulting mac_key_length is 0 bytes,
//   enc_key_length is 32 bytes and fixed_iv_length is 4 bytes.
#define HSM_KDF_HMAC_SHA_384_TLS_0_32_4 \
	((hsm_kdf_algo_id_t)0x21u)

//!< TLS PRF based on HMAC with SHA-256, the resulting mac_key_length is 0 bytes,
//   enc_key_length is 32 bytes and fixed_iv_length is 4 bytes.
#define HSM_KDF_HMAC_SHA_256_TLS_0_32_4 \
	((hsm_kdf_algo_id_t)0x22u)

//!< TLS PRF based on HMAC with SHA-256, the resulting mac_key_length is 32 bytes,
//   enc_key_length is 16 bytes and fixed_iv_length is 4 bytes.
#define HSM_KDF_HMAC_SHA_256_TLS_32_16_4 \
	((hsm_kdf_algo_id_t)0x23u)

//!< TLS PRF based on HMAC with SHA-384, the resulting mac_key_length is 48 bytes,
//   enc_key_length is 32 bytes and fixed_iv_length is 4 bytes.
#define HSM_KDF_HMAC_SHA_384_TLS_48_32_4 \
	((hsm_kdf_algo_id_t)0x24u)

//!< One-Step Key Derivation using SHA256 as per NIST SP80056C. It can only be used,
//   together with a signed message, to generate KEKs (key encryption keys) for
//   key injection (hsm_manage_key API).
#define HSM_KDF_ONE_STEP_SHA_256 \
	((hsm_kdf_algo_id_t)0x31u)

#define HSM_KE_SCHEME_ECDH_NIST_P256 \
	((hsm_key_exchange_scheme_id_t)0x02u)

#define HSM_KE_SCHEME_ECDH_NIST_P384 \
	((hsm_key_exchange_scheme_id_t)0x03u)

#define HSM_KE_SCHEME_ECDH_BRAINPOOL_R1_256 \
	((hsm_key_exchange_scheme_id_t)0x13u)

#define HSM_KE_SCHEME_ECDH_BRAINPOOL_R1_384 \
	((hsm_key_exchange_scheme_id_t)0x15u)

#define HSM_KE_SCHEME_ECDH_BRAINPOOL_T1_256 \
	((hsm_key_exchange_scheme_id_t)0x23u)

#define HSM_KE_SCHEME_SM2_FP_256 \
	((hsm_key_exchange_scheme_id_t)0x42u)

//!< User can replace an existing key only by the derived key which should have
//   the same type of the original one.
#define HSM_OP_KEY_EXCHANGE_FLAGS_UPDATE \
	((hsm_op_key_exchange_flags_t)(1u << 0))

//!< Create a new key
#define HSM_OP_KEY_EXCHANGE_FLAGS_CREATE \
	((hsm_op_key_exchange_flags_t)(1u << 1))

//!< Use an ephemeral key (freshly generated key)
#define HSM_OP_KEY_EXCHANGE_FLAGS_GENERATE_EPHEMERAL \
	((hsm_op_key_exchange_flags_t)(1u << 2))

//!< Enable key confirmation (valid only in case of HSM_KE_SCHEME_SM2_FP_256)
#define HSM_OP_KEY_EXCHANGE_FLAGS_KEY_CONF_EN \
	((hsm_op_key_exchange_flags_t)(1u << 3))

//!< Use extended master secret for TLS KDFs
#define HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS  \
	((hsm_op_key_exchange_flags_t)(1u << 4))

//!< The request is completed only when the new key has been written in the NVM.
//   This applicable for persistent key only.
#define HSM_OP_KEY_EXCHANGE_FLAGS_STRICT_OPERATION \
	((hsm_op_key_exchange_flags_t)(1u << 7))

typedef uint8_t hsm_op_tls_finish_algo_id_t;
typedef uint8_t hsm_op_tls_finish_flags_t;
typedef struct {
	//!< identifier of the master_secret key used for the PRF.
	uint32_t                    key_identifier;
	//!< pointer to the input area containing the hash of the handshake messages.
	uint8_t                     *handshake_hash_input;
	//!< pointer to the output area where the verify_data contents will be written.
	uint8_t                     *verify_data_output;
	//!< size of the hash of the handshake messages
	uint16_t                    handshake_hash_input_size;
	//!< size of the required verify_data output
	uint16_t                    verify_data_output_size;
	//!< bitmap specifying the operation properties
	hsm_op_tls_finish_flags_t   flags;
	//!< hash algorithm to be used for the PRF
	hsm_op_tls_finish_algo_id_t hash_algorithm;
	//!< It must be 0.
	uint8_t                     reserved[2];
} op_tls_finish_args_t;

/**
 * This command is designed to compute the verify_data block required for the
 * Finished message in the TLS handshake.\n
 * The input key must be a master_secret key generated by a previous hsm_key_exchange
 * call using a TLS KDF.\n
 * User can call this function only after having opened a key management service flow.\n
 *
 * \param key_management_hdl handle identifying the key store management service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_tls_finish(hsm_hdl_t key_management_hdl,
			 op_tls_finish_args_t *args);

#define HSM_OP_TLS_FINISH_HASH_ALGO_SHA256              (0x06)
#define HSM_OP_TLS_FINISH_HASH_ALGO_SHA384              (0x07)
//!< Use "client finished" label for PRF
#define HSM_OP_TLS_FINISH_FLAGS_CLIENT                  BIT(0)
//!< Use "server finished" label for PRF
#define HSM_OP_TLS_FINISH_FLAGS_SERVER                  BIT(1)

/**
 *\addtogroup qxp_specific
 * \ref group20
 *
 * - \ref HSM_KDF_HMAC_SHA_256_TLS_0_16_4 is not supported.
 * - \ref HSM_KDF_HMAC_SHA_384_TLS_0_32_4 is not supported.
 * - \ref HSM_KDF_HMAC_SHA_256_TLS_0_32_4 is not supported.
 * - \ref HSM_KDF_HMAC_SHA_256_TLS_32_16_4 is not supported.
 * - \ref HSM_KDF_HMAC_SHA_384_TLS_48_32_4 is not supported.
 * - \ref hsm_tls_finish API is not supported.
 * - \ref HSM_OP_TLS_FINISH_HASH_ALGO_SHA256 is not supported.
 * - \ref HSM_OP_TLS_FINISH_HASH_ALGO_SHA384 is not supported.
 * - \ref HSM_OP_TLS_FINISH_FLAGS_CLIENT is not supported.
 * - \ref HSM_OP_TLS_FINISH_FLAGS_SERVER is not supported.
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
 * - \ref hsm_tls_finish API is not supported.
 * - \ref HSM_OP_TLS_FINISH_HASH_ALGO_SHA256 is not supported.
 * - \ref HSM_OP_TLS_FINISH_HASH_ALGO_SHA384 is not supported.
 * - \ref HSM_OP_TLS_FINISH_FLAGS_CLIENT is not supported.
 * - \ref HSM_OP_TLS_FINISH_FLAGS_SERVER is not supported.
 */
/** @} end of key exchange operation */

/**
 *  @defgroup group21 Standalone butterfly key expansion
 * @{
 */

typedef uint8_t hsm_op_st_but_key_exp_flags_t;
typedef struct {
	//!< identifier of the key to be expanded.
	uint32_t key_identifier;
	//!< identifier of the key to be use for the expansion function computation
	uint32_t expansion_fct_key_identifier;
	//!< pointer to the input used to compute the expansion function
	uint8_t *expansion_fct_input;
	//!< pointer to the hash value input.\n In case of explicit certificate,
	//   the hash value address must be set to 0.
	uint8_t *hash_value;
	//!< pointer to the private reconstruction value input.\n
	//   In case of explicit certificate, the pr_reconstruction_value address
	//   must be set to 0.
	uint8_t *pr_reconstruction_value;
	//!< length in bytes of the expansion function input. \n
	//   It msut be 16 bytes.
	uint8_t expansion_fct_input_size;
	//!< length in bytes of the hash value input.\n
	//   In case of explicit certificate, the hash_value_size parameter must
	//   be set to 0.
	uint8_t hash_value_size;
	//!< length in bytes of the private reconstruction value input.\n
	//   In case of explicit certificate, the pr_reconstruction_value_size
	//   parameter must be set to 0.
	uint8_t pr_reconstruction_value_size;
	//!< bitmap specifying the operation properties
	hsm_op_st_but_key_exp_flags_t flags;
	//!< pointer to identifier of the derived key to be used for the operation.\n
	//   In case of create operation the new destination key identifier will
	//   be stored in this location.
	uint32_t *dest_key_identifier;
	//!< pointer to the output area where the public key must be written.
	uint8_t *output;
	//!< length in bytes of the generated key, if the size is 0, no key is
	//   copied in the output.
	uint16_t output_size;
	//!< indicates the type of the key to be derived.
	hsm_key_type_t key_type;
	//!< cipher algorithm to be used for the expansion function computation
	uint8_t expansion_fct_algo;
	//!< it must be a value in the range 0-1023. Keys belonging to the same
	//   group can be cached in the HSM local memory through the
	//   hsm_manage_key_group API
	hsm_key_group_t key_group;
	//!< bitmap specifying the properties of the derived key.
	hsm_key_info_t key_info;
} op_st_butt_key_exp_args_t;

/**
 * This command is designed to perform a standalone butterfly key expansion
 * operation on an ECC private key in case of implicit and explicit certificates.
 * Optionally the resulting public key is exported.
 * The standalone butterfly key expansion computes the expansion function in
 * addition to the butterfly key expansion
 *
 * The expansion function is defined as:
 * f_k = (cipher(k, x+1) xor (x+1)) || (cipher(k, x+2) xor (x+2)) ||
 *       (cipher(k, x+3) xor (x+3))  mod l
 *   where,
 *   - Cipher = AES 128 ECB or SM4 128 ECB
 *   - K: the expansion function key
 *   - X: is expansion function the input
 *   - l: the order of the group of points on the curve.\n
 * User can call this function only after having opened a key management service flow. \n\n
 *
 * Explicit certificates:
 *  - f_k = expansion function value
 *
 * out_key = Key  + f_k
 * \n\n
 *
 * Implicit certificates:
 *  - f_k = expansion function value,
 *  - hash = hash value used in the derivation of the pseudonym ECC key,
 *  - pr_v = private reconstruction value
 *
 * out_key = (Key  + f_k)*hash + pr_v
 *
 * \param key_management_hdl handle identifying the key store management
 * service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_standalone_butterfly_key_expansion(hsm_hdl_t key_management_hdl,
						 op_st_butt_key_exp_args_t *args);
//!< User can replace an existing key only by generating a key with the same
//type of the original one.
#define HSM_OP_ST_BUTTERFLY_KEY_FLAGS_UPDATE \
	((hsm_op_st_but_key_exp_flags_t)(1u << 0))
//!< Create a new key.
#define HSM_OP_ST_BUTTERFLY_KEY_FLAGS_CREATE \
	((hsm_op_st_but_key_exp_flags_t)(1u << 1))
//!< standalone butterfly key expansion using implicit certificate.
#define HSM_OP_ST_BUTTERFLY_KEY_FLAGS_IMPLICIT_CERTIF \
	((hsm_op_st_but_key_exp_flags_t)(0u << 2))
//!< standalone butterfly key expansion using explicit certificate.
#define HSM_OP_ST_BUTTERFLY_KEY_FLAGS_EXPLICIT_CERTIF \
	((hsm_op_st_but_key_exp_flags_t)(1u << 2))
//!< The request is completed only when the new key has been written in the NVM.
#define HSM_OP_ST_BUTTERFLY_KEY_FLAGS_STRICT_OPERATION \
	((hsm_op_st_but_key_exp_flags_t)(1u << 7))

/**
 *\addtogroup qxp_specific
 * \ref group21
 *
 * - \ref This API is not supported.
 *
 */

/**
 *\addtogroup dxl_specific
 * \ref group21
 *
 * \ref hsm_key_type_t of op_butt_key_exp_args_t: Only following are supported:
 * - HSM_KEY_TYPE_ECDSA_NIST_P256,
 * - HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256 and
 * - HSM_KEY_TYPE_DSA_SM2_FP_256.
 *
 */
/** @} end of Standalone butterfly key expansion */

/**
 *  @defgroup group22 Key generic crypto service
 * @{
 */
typedef uint8_t hsm_svc_key_generic_crypto_flags_t;
typedef struct {
	//!< bitmap indicating the service flow properties
	hsm_svc_key_generic_crypto_flags_t flags;
	uint8_t reserved[3];
} open_svc_key_generic_crypto_args_t;

/**
 * Open a generic crypto service flow. \n
 * User can call this function only after having opened a session.\n
 * User must open this service in order to perform key generic cryptographic
 * operations.
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 * \param key_generic_crypto_hdl pointer to where the key generic cryto service
 * flow handle must be written.
 *
 * \return error code
 */
hsm_err_t hsm_open_key_generic_crypto_service(hsm_hdl_t session_hdl,
					      open_svc_key_generic_crypto_args_t *args,
					      hsm_hdl_t *key_generic_crypto_hdl);

/**
 *\addtogroup qxp_specific
 * \ref group22
 *
 * - \ref This API is not supported.
 *
 */

/**
 * Terminate a previously opened key generic service flow.
 *
 * \param key_generic_crypto_hdl handle identifying the key generic service
 * flow to be closed.
 *
 * \return error code
 */
hsm_err_t hsm_close_key_generic_crypto_service(hsm_hdl_t key_generic_crypto_hdl);

/**
 *\addtogroup qxp_specific
 * \ref group22
 *
 * - \ref This API is not supported.
 *
 */

typedef uint8_t hsm_op_key_generic_crypto_algo_t;
typedef uint8_t hsm_op_key_generic_crypto_flags_t;
typedef struct {
	//!< pointer to the key to be used for the cryptographic operation
	uint8_t *key;
	//!< length in bytes of the key
	uint8_t key_size;
	//!< pointer to the initialization vector
	uint8_t *iv;
	//!< length in bytes of the initialization vector
	uint16_t iv_size;
	//!< pointer to the additional authentication data
	uint8_t *aad;
	//!< length in bytes of the additional authentication data
	uint16_t aad_size;
	//!< length in bytes of the tag
	uint8_t tag_size;
	//!< algorithm to be used for the cryptographic operation
	hsm_op_key_generic_crypto_algo_t crypto_algo;
	//!< bitmap specifying the cryptographic operation attributes
	hsm_op_key_generic_crypto_flags_t flags;
	//!< pointer to the input area\n plaintext for encryption
	//ciphertext + tag for decryption
	uint8_t *input;
	//!< pointer to the output area\n ciphertext + tag for encryption
	//plaintext for decryption if the tag is verified
	uint8_t *output;
	//!< length in bytes of the input
	uint32_t input_size;
	//!< length in bytes of the output
	uint32_t output_size;
	uint32_t reserved;
} op_key_generic_crypto_args_t;

/**
 * Perform key generic crypto service operations\n
 * User can call this function only after having opened a key generic
 * crypto service flow\n
 *
 * \param key_generic_crypto_hdl handle identifying the key generic
 * cryto service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_key_generic_crypto(hsm_hdl_t key_generic_crypto_hdl,
				 op_key_generic_crypto_args_t *args);

//!< Perform SM4 CCM with following characteristics:
// SM4 CCM where AAD supported,
// Tag len = {4, 6, 8, 10, 12, 14, 16} bytes,
// IV len = {7, 8, 9, 10, 11, 12, 13} bytes
#define HSM_KEY_GENERIC_ALGO_SM4_CCM \
	((hsm_op_key_generic_crypto_algo_t)(0x10u))
#define HSM_KEY_GENERIC_FLAGS_DECRYPT \
	((hsm_op_key_generic_crypto_flags_t)(0u << 0))
#define HSM_KEY_GENERIC_FLAGS_ENCRYPT \
	((hsm_op_key_generic_crypto_flags_t)(1u << 0))

/**
 *\addtogroup qxp_specific
 * \ref group22
 *
 * - \ref This API is not supported.
 *
 */

/** @} end of Key generic crypto service flow */

/** \}*/
#endif
#endif