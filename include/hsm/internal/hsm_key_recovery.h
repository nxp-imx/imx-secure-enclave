// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#ifndef HSM_KEY_RECOVERY_H
#define HSM_KEY_RECOVERY_H

#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_key.h"

/**
 *  @defgroup group12 Public key recovery
 * @{
 *
 * Public Key Recovery is now also known as Public Key Exportation, in PSA
 * compliant APIs. The naming here has been kept unchanged, for backward
 * compatibility and Non-PSA compliant APIs.\n
 *
 */
typedef uint8_t hsm_op_pub_key_recovery_flags_t;
typedef struct {
	//!< pointer to the identifier of the key to be used for the operation
	uint32_t key_identifier;
	//!< pointer to the output area where the generated public key must be written
	uint8_t *out_key;
	//!< length in bytes of the output key
	uint16_t out_key_size;
#ifndef PSA_COMPLIANT
	//!< indicates the type of the key to be recovered
	hsm_key_type_t key_type;
	//!< bitmap specifying the operation attributes, mandatory for non-PSA compliant platforms
	hsm_op_pub_key_recovery_flags_t flags;
#endif
} op_pub_key_recovery_args_t;

/**
 * Recover Public key from private key present in key store \n
 * User can call this function only after having opened a key store.\n
 *
 * \param key_store_hdl handle identifying the current key store.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_pub_key_recovery(hsm_hdl_t key_store_hdl, op_pub_key_recovery_args_t *args);
/** @} end of Public key recovery operation */

#endif
