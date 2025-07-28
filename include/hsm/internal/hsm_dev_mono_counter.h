// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef HSM_DEV_MONO_COUNTER_H
#define HSM_DEV_MONO_COUNTER_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"

/**
 *  @defgroup group37 Mono Counter
 * @{
 */

/**
 * Structure detailing the device mono counter operation member arguments
 */
typedef struct {
	uint8_t ele_hsm_fuse_word;
	//!< Count of ELE HSM fuse word
	uint8_t v2x_hsm_fuse_word;
	//!< Count of V2X HSM fuse word
	uint8_t v2x_she_fuse_word;
	//!< Count of V2X SHE fuse word
	//!< Sum of above three should not exceed
	//!< total available monotonic counter fuse words on the board
	uint8_t enforce_fuse;
	//!< Set this flag if want to configure any ELE/V2X counter to zero
	uint8_t warning;
	//!< Warning returned by the mono counter operation
} op_dev_mono_counter_args_t;

/**
 * Perform mono counter operation
 * User can call this function only after having opened the session.
 * This function is used to partition monotonic counter fuse words between HSMs.
 * The config can only be issued once per device.
 * If no config is present in OTP and a monotonic counter operation is triggered,
 * a warning will be issued and no rollback protection will be applied.
 *
 * If a valid configuration has already been issued, then the written config is returned.
 * All available monotonic counter fuse words must be used.
 * If the sum of the configured fuse words is different than the total amount available,
 * the config will be considered invalid.
 *
 * A nill config (all HSM words at 0) is considered as a read config operation and will
 * succeed on a provisioned device.
 * If no existing config exists, it will fail.
 *
 * \param sess_hdl handle identifying the active session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

hsm_err_t hsm_dev_mono_counter(hsm_hdl_t sess_hdl, op_dev_mono_counter_args_t *args);

/** @} end of dev mono counter operation */
#endif
