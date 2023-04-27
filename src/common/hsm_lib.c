// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
 */

#include <string.h>

#include "hsm_api.h"

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"

#include "sab_common_err.h"
#include "sab_msg_def.h"
#include "sab_messaging.h"
#include "sab_process_msg.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

void __attribute__((constructor)) libele_hsm_start()
{
	int msg_type_id;

	se_info("\nlibele_hsm constructor\n");

	for (msg_type_id = ROM_MSG; msg_type_id < MAX_MSG_TYPE;
	     msg_type_id++) {
		init_sab_hsm_msg_engine(msg_type_id);
	}

}

void __attribute__((destructor)) libele_hsm_end()
{
	se_info("\nlibele_hsm destructor\n");
}
