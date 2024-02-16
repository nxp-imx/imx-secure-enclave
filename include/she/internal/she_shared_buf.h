// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef SHE_SHARED_BUF_H
#define SHE_SHARED_BUF_H

/**
 * @defgroup group10 Shared Buffer
 * Shared Memory and shared buffer
 *
 * This is applicable for SECO only not valid for V2X (i.MX95)
 * @{
 */

/**
 * Structure describing the get shared buffer operation arguments
 */
typedef struct {
	uint16_t shared_buf_offset;
	//!< offset of the shared buffer in secure memory
	uint16_t shared_buf_size;
	//!< size in bytes of the allocated shared buffer
} op_shared_buf_args_t;

/** @} end of shared buffer group */
#endif
