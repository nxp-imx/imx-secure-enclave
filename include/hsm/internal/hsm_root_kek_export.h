// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_ROOT_KEK_EXPORT_H
#define HSM_ROOT_KEK_EXPORT_H

#include "internal/hsm_common_def.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"

/**
 *  @defgroup group14 Root KEK export
 * @{
 */

/**
 * Bit map indicating the export root kek attributes
 */
typedef uint8_t hsm_op_export_root_kek_flags_t;

/**
 * Structure describing the export root kek operation arguments
 */
typedef struct {
	uint8_t *signed_message;
	//!< pointer to signed_message authorizing the operation
	uint8_t *out_root_kek;
	//!< pointer to the output area where the derived root kek
	//!< (key encryption key) must be written
	int16_t signed_msg_size;
	//!< size of the signed_message authorizing the operation
	uint8_t root_kek_size;
	//!< length in bytes of the root kek. Must be 32 bytes.
	hsm_op_export_root_kek_flags_t flags;
	//!< flags bitmap specifying the operation attributes.
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
/**
 * Bit indicating the export root common kek
 */
#define HSM_OP_EXPORT_ROOT_KEK_FLAGS_COMMON_KEK \
		((hsm_op_export_root_kek_flags_t)(1u << 0))
/**
 * Bit indicating the export root unique kek
 */
#define HSM_OP_EXPORT_ROOT_KEK_FLAGS_UNIQUE_KEK \
		((hsm_op_export_root_kek_flags_t)(0u << 0))
/** @} end of export root key encryption key operation */
#endif
