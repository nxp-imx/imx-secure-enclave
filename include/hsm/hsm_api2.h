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
