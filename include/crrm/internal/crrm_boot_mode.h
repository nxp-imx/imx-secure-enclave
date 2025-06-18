// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef CRRM_BOOT_MODE_H
#define CRRM_BOOT_MODE_H

#include "internal/hsm_utils.h"

/**
 *  @defgroup group1 Boot Mode
 * @{
 */

#define NORMAL_BOOT_MODE		0x69
#define RECOVERY_DOWNLOAD_BOOT_MODE	0x3c
#define RECOVERY_INSTALL_BOOT_MODE	0x5a
/**
 * Structure describing the get boot mode operation member arguments
 */
typedef struct {
	uint8_t boot_mode;
	//!< Stores the boot mode
	//!< Indicates the reason for the previous boot:
	//!<  - 0x69 = Normal (no CRRM events)
	//!<  - 0x3c = Recovery download (timeout of CRRM watchdog)
	//!<  - 0x5a = Recovery install (recovery image available)
	//!<  - Other values reserved
	uint8_t timer_id;
	//!< If the current mode was entered due to timer expiry,
	//!< provides the ID of the timer.
	//!< Value 0xFF indicates no timer expired.
} op_get_boot_mode_args_t;

/**
 * Structure describing the set boot mode operation member arguments
 */
typedef struct {
	uint8_t new_boot_mode;
	//!< Stores the new boot mode to be set
	//!<  - 0x69 = Normal
	//!<  - 0x3c = Recovery download
	//!<  - 0x5a = Recovery install
	//!<  - All other values reserved
	uint8_t stored_boot_mode;
	//!< Indicates the stored boot mode (may be different from
	//!< requested mode if forbidden transition requested):
	//!<  - 0x69 = Normal
	//!<  - 0x3c = Recovery download
	//!<  - 0x5a = Recovery install
	//!<  - All other values reserved
} op_set_boot_mode_args_t;

/**
 * Perform get boot mode operation\n
 * User can call this function only after CRRM init has been done.
 *
 * \param crrm_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

hsm_err_t crrm_get_boot_mode(hsm_hdl_t crrm_hdl, op_get_boot_mode_args_t *args);

/**
 * Perform set boot mode operation\n
 * User can call this function only after CRRM init has been done.
 *
 * \param crrm_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

hsm_err_t crrm_set_boot_mode(hsm_hdl_t crrm_hdl, op_set_boot_mode_args_t *args);

/** @} end of Boot Mode operation */
#endif
