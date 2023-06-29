// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_SHARED_BUF_H
#define SHE_SHARED_BUF_H

/**
 * Structure describing the get shared buffer operation arguments
 */
typedef struct {
	// offset of the shared buffer in secure memory
	uint16_t shared_buf_offset;
	// size in bytes of the allocated shared buffer
	uint16_t shared_buf_size;
} op_shared_buf_args_t;

#endif
