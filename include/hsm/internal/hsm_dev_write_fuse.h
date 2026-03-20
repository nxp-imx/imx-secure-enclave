// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024, 2026 NXP
 */

#ifndef HSM_DEV_WRITE_FUSE_H
#define HSM_DEV_WRITE_FUSE_H

#include "hsm_handle.h"
#include "hsm_key.h"
#include "hsm_utils.h"

/**
 *  @defgroup group32 Write Fuse
 * @{
 */

/**
 * Structure detailing the device write fuse operation member arguments
 */
typedef struct {
	uint16_t  processed_idx;
	//!< Last processed fuse. Value is valid if != 0xffff
	//!< In case of failure, it can indicate which fuse triggered the error.
	//!< In case of success, it provide the last fused word index.
	uint16_t word_pos;
	//!< Fuse identifier expressed as its position in word in the fuse map.
	uint16_t bit_pos;
	//!< Fuse identifier expressed as its position in bit in the fuse map.
	uint16_t bit_len;
	//!< contains bit length.
	uint32_t  payload[];
	//!< payload.
} op_dev_write_fuse_args_t;

/**
 * Perform write fuse operation\n
 * User can call this function only after having opened the session.
 *
 * \param sess_hdl handle identifying the active session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

hsm_err_t hsm_dev_write_fuse(hsm_hdl_t sess_hdl, op_dev_write_fuse_args_t *args);

/** @} end of dev write fuse operation */
#endif
