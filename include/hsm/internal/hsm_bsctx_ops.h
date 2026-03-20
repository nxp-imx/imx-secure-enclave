// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef HSM_BOOT_STAGE_CTX_OPS_H
#define HSM_BOOT_STAGE_CTX_OPS_H

#include "hsm_handle.h"
#include "hsm_utils.h"

/**
 *  @defgroup group36 BOOT-STAGE Context operation
 * @{
 */

/**
 * Enum describing the mode of operation: set or get boot-stage context value.
 */
typedef enum {
	HSM_OP_BOOT_STAGE_CTX_SET_VAL = 0x55,
	HSM_OP_BOOT_STAGE_CTX_GET_VAL = 0xAA,
} hsm_op_code_bs_ctx_t;

/**
 * Structure specifying for the boot stage context operation request.
 */
typedef struct {
	uint8_t op_code;
	//!< Operation code to specify if HSM_OP_BOOT_STAGE_CTX_SET_VAL, or
	//!<                              HSM_OP_BOOT_STAGE_CTX_GET_VAL.
	uint32_t bs_ctx_val;
	//!< Value to be written in context when HSM_OP_BOOT_STAGE_CTX_SET_VAL,
	//!< operation is set.
	uint32_t exp_bs_ctx_val;
	//!< Value read from the context when HSM_OP_BOOT_STAGE_CTX_GET_VAL,
	//!< operation is set.
} op_boot_stage_ctx_args_t;

/**
 * \param session_hdl handle identifying the session handle.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_bsctx_ops(hsm_hdl_t session_hdl, op_boot_stage_ctx_args_t *args);

/** @} end of boot-stage context operation */
#endif //HSM_BOOT_STAGE_CTX_OPS_H
