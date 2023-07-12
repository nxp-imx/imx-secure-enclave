// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_UTILS_SERVICE_H
#define SHE_UTILS_SERVICE_H

#include <internal/she_utils.h>
#include <internal/she_handle.h>

/**
 * @defgroup group3 Utils
 * User must open a SHE utils service flow in order to perform the following
 * operations:
 * - Create a utils handle
 * - perform SHE key update extension
 * - update SHE plain key
 * - export SHE plain key
 * - get SHE identity (UID)
 * - get SHE status register
 * - perform MAC generation and verification in fast mode for a SHE session on V2X
 * - perform MAC generation and verification in fast mode for a SHE session
 * @{
 */

/**
 * Structure describing the open utils service operation arguments
 */
typedef struct {
	uint32_t utils_handle;
} op_open_utils_args_t;

/**
 * Open SHE utils service flow on the specified key store.
 * The SHE utils service flow can be opened only after opening SHE key storage handle.
 *
 * \param session_hdl pointer to the handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code.
 */
she_err_t she_open_utils(she_hdl_t session_hdl, op_open_utils_args_t *args);

/**
 * Terminate a previously opened utils service flow
 *
 * \param session_hdl: pointer to the handle identifying the current session.
 *
 * \return error code.
 */
she_err_t she_close_utils(she_hdl_t session_hdl);

/** @} end of utils group */
#endif
