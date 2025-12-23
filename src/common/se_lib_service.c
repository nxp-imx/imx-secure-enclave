// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdbool.h>
#include <stdio.h>

#include "common/global_info.h"
#include "common/se_lib_service.h"
#include "common/se_lib_utils.h"

#include "sab_process_msg.h"
#include "se_lib_serv_intern.h"

static struct se_lib_service_hdl_s se_lib_services[SE_LIB_MAX_SERVICES] = {};

struct se_lib_service_hdl_s *se_lib_serv_hdl_to_ptr(se_lib_hdl_t se_lib_serv_hdl)
{
	uint32_t i;
	struct se_lib_service_hdl_s *ret;

	ret = NULL;

	if (se_lib_serv_hdl == 0)
		return ret;

	for (i = 0u; i < SE_LIB_MAX_SERVICES; i++) {
		if (se_lib_serv_hdl == se_lib_services[i].se_lib_serv_hdl) {
			if (se_lib_services[i].phdl)
				ret = &se_lib_services[i];
			break;
		}
	}
	return ret;
}

struct se_lib_service_hdl_s *add_se_lib_service(void)
{
	uint32_t i;
	struct se_lib_service_hdl_s *s_ptr = NULL;

	for (i = 0u; i < SE_LIB_MAX_SERVICES; i++) {
		if (!se_lib_services[i].phdl &&
		    !se_lib_services[i].se_lib_serv_hdl) {
			/* Found an empty slot. */
			s_ptr = &se_lib_services[i];
			break;
		}
	}
	return s_ptr;
}

static void del_se_lib_service(struct se_lib_service_hdl_s *s_ptr)
{
	if (s_ptr) {
		s_ptr->se_lib_serv_hdl = 0u;
		s_ptr->phdl = NULL;
		plat_os_abs_memset((uint8_t *)&s_ptr->mu_params, 0,
				   sizeof(struct plat_mu_params));
	}
}

uint32_t se_lib_close_service(se_lib_hdl_t se_lib_serv_hdl)
{
	struct se_lib_service_hdl_s *s_ptr;
	se_lib_err_t err = SE_LIB_UNKNOWN_HANDLE;

	do {
		if (!se_lib_serv_hdl)
			break;

		s_ptr = se_lib_serv_hdl_to_ptr(se_lib_serv_hdl);
		if (!s_ptr || !s_ptr->phdl)
			break;

		plat_os_abs_close_session(s_ptr->phdl);

		del_se_lib_service(s_ptr);
		err = SE_LIB_NO_ERROR;

	} while (false);

	return err;
}

uint32_t se_lib_open_service(open_se_lib_serv_args_t *args, se_lib_hdl_t *se_lib_serv_hdl)
{
	struct se_lib_service_hdl_s *s_ptr = NULL;
	se_lib_err_t err = SE_LIB_ERROR;

	do {
		if (!args || !se_lib_serv_hdl)
			break;

		s_ptr = add_se_lib_service();
		if (!s_ptr)
			break;

		s_ptr->mu_type = args->mu_type;
		plat_os_abs_memset((uint8_t *)&s_ptr->mu_params, 0,
				   sizeof(struct plat_mu_params));

		s_ptr->phdl = plat_os_abs_open_mu_channel(s_ptr->mu_type,
							  &s_ptr->mu_params);
		if (!s_ptr->phdl) {
			del_se_lib_service(s_ptr);
			break;
		}
		err = SE_LIB_NO_ERROR;
		*se_lib_serv_hdl = *((uint32_t *)&s_ptr);
		s_ptr->se_lib_serv_hdl = *se_lib_serv_hdl;
		args->se_lib_serv_hdl = *se_lib_serv_hdl;
	} while (false);

	if (err == SE_LIB_NO_ERROR)
		populate_global_info(*se_lib_serv_hdl);

	return err;
}
