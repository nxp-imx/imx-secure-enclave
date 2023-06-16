// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "sab_msg_def.h"
#include "sab_process_msg.h"

#if MT_SAB_SESSION
#include "sab_session.h"
#endif

static  int init_proc_sab_she_msg_engine(msg_type_t msg_type,
					 uint32_t msg_id)
{
	int ret = NOT_DONE;

	switch (msg_id) {
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

void init_sab_she_msg_engine(msg_type_t msg_type)
{
	if (msg_type > NOT_SUPPORTED && msg_type >= MAX_MSG_TYPE)
		return;

	switch (msg_type) {
	case 2:
		init_proc_sab_msg_cmd_eng(msg_type, SAB_MSG_MAX_ID,
					  init_proc_sab_she_msg_engine);
		break;
	default:
		return;
	}
}
