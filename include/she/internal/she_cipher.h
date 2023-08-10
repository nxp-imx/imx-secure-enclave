// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_CIPHER_H
#define SHE_CIPHER_H

#include "internal/she_handle.h"
#include "common/cipher.h"

/**
 * @defgroup group4 Ciphering
 * @{
 */

/**
 * - Open a cipher service flow.
 * - User can call this function only after having opened a key-store
 *   service flow.
 * - User must open this service in order to perform cipher operation.
 *
 * \param session_hdl: handle identifying the SHE session.
 * \param args: pointer to the structure containing the function arguments.
 *
 * \return error code.
 */
she_err_t she_open_cipher_service(she_hdl_t session_hdl,
				  open_svc_cipher_args_t *args);

/**
 * Terminate a previously opened cipher service flow
 *
 * \param session_hdl: pointer to handle identifying the SHE session.
 *
 * \return error code.
 */
she_err_t she_close_cipher_service(she_hdl_t session_hdl);

/** @} end of Ciphering */
#endif
