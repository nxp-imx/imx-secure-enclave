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

void __attribute__((constructor)) lib_crrm_start()
{
	int msg_type_id;

	se_info("\nlib_crrm constructor\n");

	for (msg_type_id = ROM_MSG; msg_type_id < MAX_MSG_TYPE;
	     msg_type_id++) {
		init_sab_crrm_msg_engine(msg_type_id);
	}
}

void __attribute__((destructor)) lib_crrm_end()
{
	se_info("\nlib_crrm destructor\n");
}
