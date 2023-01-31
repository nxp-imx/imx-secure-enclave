/*
 * Copyright 2022-2023 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#include "sab_msg_def.h"
#include "sab_process_msg.h"

#if MT_SAB_STORAGE_MASTER_IMPORT
#include "sab_storage_master_import.h"
#endif

static int init_proc_sab_nvm_msg_engine(msg_type_t msg_type, uint32_t msg_id)
{
	int ret = NOT_DONE;

	switch (msg_id) {
#if MT_SAB_STORAGE_MASTER_IMPORT
	case SAB_STORAGE_MASTER_IMPORT_REQ:
		if (msg_type == MT_SAB_STORAGE_MASTER_IMPORT) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_STORAGE_MASTER_IMPORT,
						  prepare_msg_storage_master_import,
						  proc_msg_rsp_storage_master_import);
		}
	break;
#endif
	default:
		break;
	}

	return ret;
}

void init_sab_nvm_msg_engine(msg_type_t msg_type)
{
	int i = 0;
	int ret = NOT_DONE;

	if ((msg_type > NOT_SUPPORTED) && (msg_type >= MAX_MSG_TYPE))
		return;

	init_proc_sab_msg_cmd_eng(msg_type,
				  SAB_MSG_MAX_ID,
				  init_proc_sab_nvm_msg_engine);
}

