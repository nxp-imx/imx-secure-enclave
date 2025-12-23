// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef SE_LIB_UTILS_H
#define SE_LIB_UTILS_H

#include <stdint.h>

/**
 * Error codes returned by SE LIB functions.
 */
typedef enum {
	SE_LIB_NO_ERROR                        = 0x0,
	/**<Success. */
	SE_LIB_UNKNOWN_HANDLE                  = 0x7,
	/**<Unknown session/service handle. */
	SE_LIB_ERROR                       = 0xEF,
	/**< SE library failure */
} se_lib_err_t;
/** @} end of error code group */

#endif
