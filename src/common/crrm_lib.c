// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <string.h>

#include "crrm_api.h"

#include "sab_common_err.h"
#include "sab_msg_def.h"
#include "sab_messaging.h"
#include "sab_process_msg.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

#include "internal/crrm_handle.h"
#include "hsm_api.h"

crrm_hdl_t session_hdl;

void __attribute__((constructor)) lib_crrm_start()
{
	int msg_type_id;
	crrm_err_t err;
	open_session_args_t open_session_args = {0};

	for (msg_type_id = ROM_MSG; msg_type_id < MAX_MSG_TYPE;
	     msg_type_id++) {
		init_sab_crrm_msg_engine(msg_type_id);
	}

	err = hsm_open_session(&open_session_args, &session_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_session failed err:0x%x\n", err);
		return;
	}
}

void __attribute__((destructor)) lib_crrm_end()
{
	if (session_hdl && hsm_close_session(session_hdl))
		printf("Failed to close CRRM session\n");
}
