// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef SE_LIB_SERV_INTERN_H
#define SE_LIB_SERV_INTERN_H

#include <stdint.h>

#include "plat_os_abs.h"

/**
 * Structure describing the SE lib service handle members
 */
struct se_lib_service_hdl_s {
	struct plat_os_abs_hdl *phdl;
		//!< Pointer to OS device node.
	se_lib_hdl_t se_lib_serv_hdl;
		//!< Session handle.
	uint32_t mu_type;
		//!< Session MU type.
	struct plat_mu_params mu_params;
		//!< MU's Parameters where SE LIB service is opened.
};

#define SE_LIB_MAX_SERVICES	(32u)
//!< Maximum services supported.

struct se_lib_service_hdl_s *se_lib_serv_hdl_to_ptr(se_lib_hdl_t se_lib_serv_hdl);
#endif
