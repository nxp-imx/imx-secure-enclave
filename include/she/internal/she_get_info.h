// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef SHE_GET_INFO_H
#define SHE_GET_INFO_H

#include "internal/she_handle.h"
#include "common/get_info.h"

/**
 * @defgroup group25 SHE Get Info
 * Get miscellaneous information.
 *
 * This function return, among others,
 * all the information needed to build a valid signed message.
 * @{
 */

/**
 * User can call this function only after having opened the SHE session.
 *
 * \param session_hdl handle identifying the active session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */

she_err_t she_get_info(she_hdl_t session_hdl, op_get_info_args_t *args);

/** @} end of SHE get info group */
#endif
