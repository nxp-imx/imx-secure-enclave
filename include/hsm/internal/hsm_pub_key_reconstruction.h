// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef HSM_PUB_KEY_RECONSTRUCTION_H
#define HSM_PUB_KEY_RECONSTRUCTION_H

#include "internal/hsm_common_def.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_key.h"
#ifndef PSA_COMPLIANT
/**
 *  @defgroup group9 Public key reconstruction
 * @{
 */

/**
 * Bit map indicating the public key reconstruction attributes
 */
typedef uint8_t hsm_op_pub_key_rec_flags_t;

/**
 * Structure describing the public key reconstruction operation arguments
 */
typedef struct {
	uint8_t *pub_rec;
	//!< pointer to the public reconstruction value extracted from the
	//!< implicit certificate.
	uint8_t *hash;
	//!< pointer to the input hash value. In the butterfly scheme it
	//!< corresponds to the hash value calculated over PCA certificate and,
	//!< concatenated, the implicit certificat.
	uint8_t *ca_key;
	//!< pointer to the CA public key
	uint8_t *out_key;
	//!< pointer to the output area where the reconstructed public key must
	//!< be written.
	uint16_t pub_rec_size;
	//!< length in bytes of the public reconstruction value
	uint16_t hash_size;
	//!< length in bytes of the input hash
	uint16_t ca_key_size;
	//!< length in bytes of the input CA public key
	uint16_t out_key_size;
	//!< length in bytes of the output key
	hsm_key_type_t key_type;
	//!< indicates the type of the managed key.
	hsm_op_pub_key_rec_flags_t flags;
	//!< flags bitmap specifying the operation attributes.
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
#endif
#endif
