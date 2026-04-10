// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef V2X_VERSION_H
#define V2X_VERSION_H

#include "prime_utils.h"

typedef struct {
	uint8_t major;
	uint8_t minor;
	uint8_t patch;
	uint32_t commit_id;
} v2x_version_t;

prime_err_t get_v2x_version(v2x_version_t *args);

#endif
