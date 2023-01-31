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

#if MT_SAB_STORAGE_MASTER_EXPORT_REQ
#include "sab_storage_master_export.h"
#endif
#if MT_SAB_STORAGE_EXPORT_FINISH_REQ
#include "sab_storage_export_finish.h"
#endif

#if MT_SAB_STORAGE_MASTER_IMPORT
#include "sab_storage_master_import.h"
#endif

static int init_sab_nvm_rcvmsg_eng(msg_type_t msg_type,
				   uint32_t start_msg_id,
				   uint32_t msg_id)
{
	int i = 0;
	int ret = NOT_DONE;

	ret = NOT_DONE;

	switch (msg_id) {
#if MT_SAB_STORAGE_MASTER_EXPORT_REQ
	case SAB_STORAGE_MASTER_EXPORT_REQ:
		if (msg_type == MT_SAB_STORAGE_MASTER_EXPORT_REQ) {
			ret = add_sab_rcvmsg_handler((msg_id - start_msg_id),
					MT_SAB_STORAGE_MASTER_EXPORT_REQ,
					parse_cmd_prep_rsp_storage_master_export);
		}
		break;
#endif
#if MT_SAB_STORAGE_EXPORT_FINISH_REQ
	case SAB_STORAGE_EXPORT_FINISH_REQ:
		if (msg_type == MT_SAB_STORAGE_EXPORT_FINISH_REQ) {
			ret = add_sab_rcvmsg_handler((msg_id - start_msg_id),
					MT_SAB_STORAGE_EXPORT_FINISH_REQ,
					parse_cmd_prep_rsp_storage_finish_export);
		}
		break;
#endif
	default:
		break;
	}
	return ret;
}

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
	init_proc_sab_msg_rcv_eng(msg_type,
				  SAB_RCVMSG_START_ID,
				  SAB_STORAGE_NVM_LAST_CMD,
				  init_sab_nvm_rcvmsg_eng);
}

