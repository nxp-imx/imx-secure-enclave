// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_SIGN_PREPARE_H
#define HSM_SIGN_PREPARE_H

#include <stdint.h>

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_sign_gen.h"

/**
 *  @defgroup group5 Signature generation
 * @{
 */

typedef uint8_t hsm_op_prepare_signature_flags_t;
#define HSM_OP_PREPARE_SIGN_INPUT_DIGEST \
				((hsm_op_prepare_signature_flags_t)(0u << 0))
#define HSM_OP_PREPARE_SIGN_INPUT_MESSAGE \
				((hsm_op_prepare_signature_flags_t)(1u << 0))
#define HSM_OP_PREPARE_SIGN_COMPRESSED_POINT \
				((hsm_op_prepare_signature_flags_t)(1u << 1))

typedef struct {
	//!< identifier of the digital signature scheme to be used
	//   for the operation.
	hsm_signature_scheme_id_t scheme_id;
	//!< bitmap specifying the operation attributes
	hsm_op_prepare_signature_flags_t flags;
} op_prepare_sign_args_t;

/**
 * Prepare the creation of a signature by pre-calculating the operations having
 * not dependencies on the input message.
 *
 * The pre-calculated value will be stored internally and
 * used once call hsm_generate_signature. Up to 20 pre-calculated values
 * can be stored, additional preparation operations will have no effects.
 *
 * User can call this function only after having opened a
 * signature generation service flow.
 *
 * The signature S=(r,s) is stored in the format r||s||Ry where:
 * - Ry is an additional byte containing the lsb of y,
 *   Ry has to be considered valid only
 *   if the HSM_OP_PREPARE_SIGN_COMPRESSED_POINT is set.
 *
 * \param signature_gen_hdl: handle identifying the signature generation
 *                           service flow
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_prepare_signature(hsm_hdl_t signature_gen_hdl,
				op_prepare_sign_args_t *args);

/** @} end of signature generation service flow */
#endif
