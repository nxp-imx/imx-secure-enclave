// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_GET_STATUS_H
#define SHE_GET_STATUS_H

#include "internal/she_handle.h"
#include "internal/she_utils.h"

/**
 * @defgroup group100 SHE commands
 * @{
 */

/**
 * @defgroup group101 CMD_GET_STATUS
 * \ingroup group100
 * @{
 */

/**
 * Structure describing the get status operation arguments
 */
typedef struct {
	uint8_t sreg;
	//!< status register bits
	uint8_t pad[3];
	//!< padding bytes
} op_get_status_args_t;

/**
 * Command to get the content of the status register
 *
 * \param session_hdl pointer to the handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code.
 */
she_err_t she_get_status(she_hdl_t session_hdl, op_get_status_args_t *args);

/** @} end of CMD_GET_STATUS group */
/** @} end of SHE Commands group */
#endif
