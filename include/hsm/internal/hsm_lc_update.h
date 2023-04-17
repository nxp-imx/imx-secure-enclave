// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_LC_UPDATE_H
#define HSM_LC_UPDATE_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"

/**
 *  @defgroup group26 LC update
 * @{
 */
typedef enum {
	HSM_NXP_PROVISIONED_STATE = (1u << 0),
	HSM_OEM_OPEN_STATE        = (1u << 1),
	HSM_OEM_CLOSE_STATE       = (1u << 3),
	HSM_OEM_FIELD_RET_STATE   = (1u << 4),
	HSM_NXP_FIELD_RET_STATE   = (1u << 5),
	HSM_OEM_LOCKED_STATE      = (1u << 7),
} hsm_lc_new_state_t;

typedef struct {
	hsm_lc_new_state_t new_lc_state;
} op_lc_update_msg_args_t;

hsm_err_t hsm_lc_update(hsm_hdl_t session_hdl,
			op_lc_update_msg_args_t *args);

/** @} end of lc update operation */
#endif //HSM_LC_UPDATE_H
