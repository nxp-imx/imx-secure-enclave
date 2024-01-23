// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef SHE_API_H
#define SHE_API_H

#include <stdint.h>

#include "internal/she_utils.h"
#include "internal/she_handle.h"
#include "internal/she_session.h"
#include "internal/she_shared_buf.h"
#include "internal/she_key_store.h"
#include "internal/she_get_info.h"
#include "internal/she_utils_service.h"
#include "internal/she_cipher.h"
#include "internal/she_get_status.h"
#include "internal/she_rng.h"
#include "internal/she_key_update.h"
#include "internal/she_load_plain_key.h"
#include "internal/she_export_plain_key.h"
#include "internal/she_fast_mac.h"
#include "internal/she_get_id.h"

extern uint8_t she_v2x_mu;

/**
 *  @defgroup group1 Session
 *  @{
 */

/**
 *
 * \param args pointer to the structure containing the function arguments.
 * \param session_hdl pointer to where the session handle must be written.
 *
 * \return error code.
 */
she_err_t she_open_session(open_session_args_t *args, she_hdl_t *session_hdl);

/**
 * Terminate a previously opened session. All the services opened under this
   session are closed as well \n
 *
 * \param session_hdl pointer to the handle identifying the session to be closed.
 *
 * \return error code.
 */
she_err_t she_close_session(she_hdl_t session_hdl);

/** @} end of session group */

/**
 *  @defgroup group11 last rating code
 *  \ingroup group100
 *  @{
 */
/**
 * Report rating code from last command
 *
 * SHE API defines standard errors that should be returned by API calls.
 * Error code reported by SECO are "translated" to these SHE error codes.
 * This API allow user to get the error code reported by SECO for the last
 * command before its translation to SHE error codes. This shoudl be used
 * for debug purpose only.
 *
 * \param session_hdl SHE session handler
 *
 * \return rating code reported by last command
 */
uint32_t she_get_last_rating_code(she_hdl_t session_hdl);

/** @} end of last rating code group */

/**
 *  @defgroup group12 CMD_CANCEL
 *  \ingroup group100
 *  @{
 */
/**
 * interrupt any given function and discard all calculations and results.
 */
void she_cmd_cancel(void);
/** @} end of CANCEL group */

#endif
