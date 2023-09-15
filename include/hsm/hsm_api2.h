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
/** \}*/
#endif
#endif
