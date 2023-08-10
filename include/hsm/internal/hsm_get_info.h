// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_GET_INFO_H
#define HSM_GET_INFO_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "common/get_info.h"

/**
 *  @defgroup group25 Get Info
 * @{
 */

/**
 * Perform device attestation operation\n
 * User can call this function only after having opened the session.
 *
 * \param sess_hdl handle identifying the active session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

hsm_err_t hsm_get_info(hsm_hdl_t sess_hdl, op_get_info_args_t *args);

/** @} end of Get info operation */
#endif
