// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_OPEN_UTILS_H
#define SHE_OPEN_UTILS_H

#include <internal/she_utils.h>
#include <internal/she_handle.h>

typedef struct {
	uint32_t utils_handle;
} op_open_utils_args_t;

she_err_t she_open_utils(she_hdl_t session_hdl, op_open_utils_args_t *args);

#endif
