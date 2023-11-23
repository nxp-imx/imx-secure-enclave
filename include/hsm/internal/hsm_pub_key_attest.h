// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_PUB_KEY_ATTEST_H
#define HSM_PUB_KEY_ATTEST_H

#include <stdint.h>

#include "internal/hsm_common_def.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"

/**
 *  @defgroup group5 Signature generation
 * @{
 */

/**
 * Enum containing the Signature Algorithms for Public Key Attestation
 */
typedef enum {
	HSM_PKEY_ATTEST_ALGO_CMAC = ALGO_CMAC,
	//!< CMAC
	HSM_PKEY_ATTEST_ALGO_ECDSA_SHA224 = ALGO_ECDSA_SHA224,
	//!< ECDSA SHA224
	HSM_PKEY_ATTEST_ALGO_ECDSA_SHA256 = ALGO_ECDSA_SHA256,
	//!< ECDSA SHA256
	HSM_PKEY_ATTEST_ALGO_ECDSA_SHA384 = ALGO_ECDSA_SHA384,
	//!< ECDSA SHA384
	HSM_PKEY_ATTEST_ALGO_ECDSA_SHA512 = ALGO_ECDSA_SHA512,
	//!< ECDSA SHA512
} hsm_pub_key_attest_sign_algo_t;

/**
 * Structure to represent the generate sign operation arguments
 */
typedef struct {
	uint32_t key_identifier;
	//!< identifier of the key to be attested
	uint32_t key_attestation_id;
	//!< identifier of the key to be used for the attestation
	hsm_pub_key_attest_sign_algo_t sign_algo;
	//!< signature algorithm to be used for the attestation
	uint8_t *auth_challenge;
	//!< pointer to the authentication challenge
	uint32_t auth_challenge_size;
	//!< authentication challenge size in bytes
	uint8_t *certificate;
	//!< pointer to the output certificate encoded as signed TLV buffer
	uint32_t certificate_size;
	//!< certificate size in bytes
	uint32_t exp_certificate_size;
	//!< expected certificate size for output, returned by FW in case of
	//!< HSM_OUT_TOO_SMALL (0x1D) error
} op_pub_key_attest_args_t;

/**
 * Attest the public key of an asymmetric key present in the ELE FW key storage.
 * User can call this function only after having opened a signature
 * generation service flow.
 *
 * \param signature_gen_hdl: handle identifying the signature generation
 *                           service flow.
 * \param args: pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_pub_key_attest(hsm_hdl_t signature_gen_hdl,
			     op_pub_key_attest_args_t *args);
/** @} end of signature generation service flow */
#endif
