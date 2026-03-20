// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef HSM_DEV_ELE_RESET_H
#define HSM_DEV_ELE_RESET_H

#include "hsm_handle.h"
#include "hsm_utils.h"

/**
 *  @defgroup group33 ELE Reset
 * @{
 */

/**
 * Perform ELE reset operation\n
 * User can call this function only after having opened the session.
 *
 * \param sess_hdl handle identifying the active session.
 *
 * \return error code
 */

hsm_err_t hsm_dev_ele_reset(hsm_hdl_t sess_hdl);

/** @} end of dev ELE reset operation */
#endif
