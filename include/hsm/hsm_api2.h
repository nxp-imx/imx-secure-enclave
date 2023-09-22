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

/** \}*/
#endif
#endif
