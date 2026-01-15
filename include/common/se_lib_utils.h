// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef SE_LIB_UTILS_H
#define SE_LIB_UTILS_H

#include <stdint.h>

/**
 * @defgroup group0 Error codes
 *
 * @{
 */

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

/**
 * Type of lib error. When SE_LIB_ERROR(0xEF) is reported,
 * the value on the second byte provides the reason behind the lib error.
 */
typedef enum {
	IO_BUF_OUT_OF_MEM     = 0x1400u,
	/**<IO Buffer setup failure. */
} lib_err_t;

/** @} end of error code group */
#endif
