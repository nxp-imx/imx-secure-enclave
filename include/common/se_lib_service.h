// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef SE_LIB_SERVICE_H
#define SE_LIB_SERVICE_H

#include <stdint.h>

/**
 *  @defgroup group39 SE lib service
 *  @{
 */

/**
 *  Define the SE lib service handle type
 */
typedef uint32_t se_lib_hdl_t;

/**
 * Structure detailing the open SE lib service operation member arguments
 */
typedef struct {
	se_lib_hdl_t se_lib_serv_hdl;
	//!< SE library service handle.
	uint8_t mu_type;
	//!< MU with associated functionality on which SE lib service to be opened.
} open_se_lib_serv_args_t;

uint32_t se_lib_open_service(open_se_lib_serv_args_t *args,
			     se_lib_hdl_t *se_lib_serv_hdl);
uint32_t se_lib_close_service(se_lib_hdl_t se_lib_serv_hdl);
#endif
