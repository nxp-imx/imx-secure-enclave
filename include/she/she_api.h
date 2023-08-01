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
#endif

#if MT_SAB_SHARED_BUF
#include "internal/she_shared_buf.h"
#endif

#if MT_SAB_KEY_STORE
#include "internal/she_key_store.h"
#endif

#if MT_SAB_GET_INFO
#include "internal/she_get_info.h"
#endif

#if MT_SAB_UTILS
#include "internal/she_utils_service.h"
#endif

#if MT_SAB_CIPHER
#include "internal/she_cipher.h"
#endif

#if MT_SAB_GET_STATUS
#include "internal/she_get_status.h"
#endif

#if MT_SAB_RNG
#include "internal/she_rng.h"
#endif

#if MT_SAB_KEY_UPDATE
#include "internal/she_key_update.h"
#endif

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

#endif
