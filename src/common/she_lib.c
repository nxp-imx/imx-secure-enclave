// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
 */

#include <string.h>

#include "she_api.h"

#include "internal/she_handle.h"
#include "internal/she_utils.h"

#include "sab_common_err.h"
#include "sab_msg_def.h"
#include "sab_messaging.h"
#include "sab_process_msg.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

void __attribute__((constructor)) lib_she_start()
{
	int msg_type_id;

	se_info("\nlib_she constructor\n");

	for (msg_type_id = SAB_MSG; msg_type_id < MAX_MSG_TYPE;
	     msg_type_id++) {
		init_sab_she_msg_engine(msg_type_id);
	}

}

void __attribute__((destructor)) lib_she_end()
{
	se_info("\nlib_she destructor\n");
}
