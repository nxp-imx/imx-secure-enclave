// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "sab_msg_def.h"
#include "sab_process_msg.h"

#if MT_SAB_STORAGE_MASTER_EXPORT_REQ
#include "sab_storage_master_export.h"
#endif
#if MT_SAB_STORAGE_EXPORT_FINISH_REQ
#include "sab_storage_export_finish.h"
#endif
#if MT_SAB_STORAGE_CHUNK_GET_REQ
#include "sab_storage_get_chunk.h"
#endif
#if MT_SAB_STORAGE_CHUNK_GET_DONE_REQ
#include "sab_storage_get_chunk_done.h"
#endif
#if MT_SAB_STORAGE_CHUNK_EXPORT_REQ
#include "sab_storage_chunk_export.h"
#endif
#if MT_SAB_STORAGE_OPEN
#include "sab_storage_open.h"
#endif
#if MT_SAB_STORAGE_CLOSE
#include "sab_storage_close.h"
#endif
#if MT_SAB_SESSION
#include "sab_session.h"
#endif

#if MT_SAB_STORAGE_MASTER_IMPORT
#include "sab_storage_master_import.h"
#endif
#if MT_SAB_STORAGE_KEY_DB_REQ
#include "sab_storage_key_db.h"
#endif

static int init_sab_nvm_rcvmsg_eng(msg_type_t msg_type,
				   uint32_t start_msg_id,
				   uint32_t msg_id)
{
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
#if MT_SAB_STORAGE_CHUNK_GET_REQ
	case SAB_STORAGE_CHUNK_GET_REQ:
		if (msg_type == MT_SAB_STORAGE_CHUNK_GET_REQ) {
			ret = add_sab_rcvmsg_handler((msg_id - start_msg_id),
					MT_SAB_STORAGE_CHUNK_GET_REQ,
					parse_cmd_prep_rsp_storage_get_chunk);
		}
		break;
#endif
#if MT_SAB_STORAGE_CHUNK_GET_DONE_REQ
	case SAB_STORAGE_CHUNK_GET_DONE_REQ:
		if (msg_type == MT_SAB_STORAGE_CHUNK_GET_DONE_REQ) {
			ret = add_sab_rcvmsg_handler((msg_id - start_msg_id),
					MT_SAB_STORAGE_CHUNK_GET_DONE_REQ,
					parse_cmd_prep_rsp_storage_get_chunk_done);
		}
		break;
#endif
#if MT_SAB_STORAGE_CHUNK_EXPORT_REQ
	case SAB_STORAGE_CHUNK_EXPORT_REQ:
 		if (msg_type == MT_SAB_STORAGE_CHUNK_EXPORT_REQ) {
			ret = add_sab_rcvmsg_handler((msg_id - start_msg_id),
					MT_SAB_STORAGE_CHUNK_EXPORT_REQ,
					parse_cmd_prep_rsp_storage_chunk_export);
 			}
 		break;
 #endif
#if MT_SAB_STORAGE_KEY_DB_REQ
	case SAB_STORAGE_KEY_DB_REQ:
		if (msg_type == MT_SAB_STORAGE_KEY_DB_REQ) {
			ret = add_sab_rcvmsg_handler((msg_id - start_msg_id),
						     MT_SAB_STORAGE_KEY_DB_REQ,
						     parse_cmd_prep_rsp_storage_key_db);
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
#if MT_SAB_STORAGE_OPEN
	case SAB_STORAGE_OPEN_REQ:
		if (msg_type == MT_SAB_STORAGE_OPEN) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_STORAGE_OPEN,
						  prepare_msg_storage_open,
						  proc_msg_rsp_storage_open);
		}
	break;
#endif
#if MT_SAB_STORAGE_CLOSE
	case SAB_STORAGE_CLOSE_REQ:
		if (msg_type == MT_SAB_STORAGE_CLOSE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_STORAGE_CLOSE,
						  prepare_msg_storage_close,
						  proc_msg_rsp_storage_close);
		}
	break;
#endif
#if MT_SAB_SESSION
	case SAB_SESSION_OPEN_REQ:
		if (msg_type == MT_SAB_SESSION) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_SESSION,
						  prepare_msg_session_open_req,
						  proc_msg_rsp_session_open_req);
		}
		break;
	case SAB_SESSION_CLOSE_REQ:
		if (msg_type == MT_SAB_SESSION) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_SESSION,
						  prepare_msg_session_close_req,
						  proc_msg_rsp_session_close_req);
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

