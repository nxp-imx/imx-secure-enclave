// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef HSM_IMPORT_PUB_KEY_H
#define HSM_IMPORT_PUB_KEY_H

#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_key.h"
#ifndef PSA_COMPLIANT
/**
 * Bit field describing the operation attributes
 */
typedef uint8_t hsm_op_import_public_key_flags_t;

/**
 * Structure describing the import public key member arguments
 */
typedef struct {
	uint32_t *key_ref;
	//!< key reference where the 4 bytes key reference to be used as
	//!< key in the hsm_verify_signature will be stored.
	uint8_t *key;
	//!< pointer to the public key to be imported
	uint16_t key_size;
	//!< length in bytes of the input key
	hsm_key_type_t key_type;
	//!< indicates the type of the key to be imported.
	hsm_op_import_public_key_flags_t flags;
	//!< bitmap specifying the operation attributes
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
 *
 * \return error code
 */
hsm_err_t hsm_import_public_key(hsm_hdl_t signature_ver_hdl,
				op_import_public_key_args_t *args);

#endif
#endif
