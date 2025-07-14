// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef HSM_BLOB_UNBLOB_H
#define HSM_BLOB_UNBLOB_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"

/**
 *  @defgroup group35 BLOB-UNBLOB
 * @{
 */

typedef uint8_t hsm_op_blob_unblob_flags_t;

#define HSM_OP_BLOB_UNBLOB_FLAG_USE_MU_IN_DER_CTX \
			((hsm_op_key_gen_flags_t)(1u << 0))
//!<  Use MU Attributes in blob-key derivation context. Blob will be binded to
//!<  MU Attributes (sec/priv, masternum, did, and MU index).

#define HSM_OP_BLOB_UNBLOB_FLAG_USE_BOOT_STAGE_IN_DER_CTX \
			((hsm_op_key_gen_flags_t)(1u << 1))
//!< Use boot stage value in derivation context.
#define HSM_OP_BLOB_UNBLOB_FLAG_USE_UUID_IN_DER_CTX \
			((hsm_op_key_gen_flags_t)(1u << 2))
//!< Use unique ID in derivation context.

/**
 * Enum describing the mode of operation: wrap or unwrap.
 */
typedef enum {
	HSM_OP_BLOB_UNBLOB_MODE_WRAP = 0x55,
	HSM_OP_BLOB_UNBLOB_MODE_UNWRAP = 0xAA,
} hsm_op_blob_unblob_mode_t;

/**
 * Structure specifying the blob-unblob request.
 */
typedef struct {
	uint32_t *in_addr;
	//!< Input address where blob or plain-text can be found.
	uint32_t *out_addr;
	//!< Output address where blob or plain-text can be found.
	uint32_t *usr_ctx_addr;
	//!< Address space, where user input to blob-key derivation context, can be found.
	uint32_t in_size;
	//!< Size in bytes of Inout.
	uint32_t out_size;
	//!< Size in bytes of Output.
	uint32_t usr_ctx_size;
	//!< Size in bytes of user-input. Can be zero.
	uint8_t flags;
	//!< Bitmap specifying the operation properties as defined by
	//!< 'hsm_op_key_gen_flags_t'.
	uint8_t mode;
	//!< Input Mode to specify: HSM_OP_BLOB_UNBLOB_MODE_WRAP, or
	//!<                        HSM_OP_BLOB_UNBLOB_MODE_UNWRAP.
	uint32_t exp_out_size;
	//!< Expected size in bytes of Output.
} op_blob_unblob_msg_args_t;

/**
 * This API enables:
 * - Creating blob by wraping a plain-text, using the wrapping key, and
 * - Un-blob, by un-wraping the blob to plain-text, using the  same wrapping key.
 *
 * \param session_hdl handle identifying the session handle.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_blob_unblob(hsm_hdl_t session_hdl,
			  op_blob_unblob_msg_args_t *args);

/** @} end of blob-unblob operation */
#endif //HSM_BLOB_UNBLOB_H
