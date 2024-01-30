// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef HSM_SM2_GET_Z_H
#define HSM_SM2_GET_Z_H

#include "internal/hsm_common_def.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_key.h"
#ifndef PSA_COMPLIANT
/**
 *  @defgroup group17 SM2 Get Z
 * @{
 */
typedef uint8_t hsm_op_sm2_get_z_flags_t;
	//!< flags type.

typedef struct {
	uint8_t *public_key;
	//!< pointer to the sender public key
	uint8_t *identifier;
	//!< pointer to the sender identifier
	uint8_t *z_value;
	//!< pointer to the output area where the Z value must be written
	uint16_t public_key_size;
	//!< length in bytes of the sender public key should be equal to 64 bytes
	uint8_t id_size;
	//!< length in bytes of the identifier
	uint8_t z_size;
	//!< length in bytes of Z should be at least 32 bytes
	hsm_key_type_t key_type;
	//!< indicates the type of the sender public key.
	//!< Only HSM_KEY_TYPE_DSA_SM2_FP_256 is supported.
	hsm_op_sm2_get_z_flags_t flags;
	//!< bitmap specifying the operation attributes.
	uint8_t reserved[2];
} op_sm2_get_z_args_t;

/**
 * This command is designed to compute:
 *  Z = SM3(Entl || ID || a || b || xG || yG || xpubk || ypubk)
 *  where,
 *  - ID, Entl: user distinguishing identifier and length,
 *  - a, b, xG and yG : curve parameters,
 *  - xpubk , ypubk : public key \n\n
 * This value is used for SM2 public key cryptography algorithms, as specified
 * in GB/T 32918.
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
#endif
#endif
