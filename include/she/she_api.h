// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_API_H
#define SHE_API_H

#include <stdint.h>

#include "internal/she_utils.h"
#include "internal/she_handle.h"

#if MT_SAB_SESSION
#include "internal/she_session.h"
#include "internal/hsm_session.h"
#endif

#if MT_SAB_SHARED_BUF
#include "internal/she_shared_buf.h"
#endif

#if MT_SAB_GET_INFO
#include "internal/hsm_get_info.h"
#endif

/**
 *
 * \param args pointer to the structure containing the function arguments.

 * \param session_hdl pointer to where the session handle must be written.
 *
 * \return error_code error code.
 */
she_err_t she_open_session(open_session_args_t *args, she_hdl_t *session_hdl);

/**
 * Terminate a previously opened session. All the services opened under this
   session are closed as well \n
 *
 * \param session_hdl pointer to the handle identifying the session to be closed.
 *
 * \return error_code error code.
 */
she_err_t she_close_session(she_hdl_t session_hdl);

#endif
