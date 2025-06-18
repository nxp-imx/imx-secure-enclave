// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "sab_msg_def.h"
#include "sab_process_msg.h"

#if MT_SAB_BOOT_MODE
#include "sab_boot_mode.h"
#endif

#if MT_SAB_GET_AWDT_STATUS
#include "sab_get_AWDT_status.h"
#endif

#if MT_SAB_GET_NONCE
#include "sab_get_nonce.h"
#endif

#if MT_SAB_REFRESH_AWDT
#include "sab_refresh_AWDT.h"
#endif

#if MT_SAB_SESSION
#include "sab_session.h"
#endif

#if MT_SAB_GET_INFO
#include "sab_get_info.h"
#endif

#if MT_SAB_DEV_GETINFO
#include "sab_dev_getinfo.h"
#endif

static int init_proc_sab_crrm_hsm_msg_engine(msg_type_t msg_type, uint32_t msg_id)
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
#if MT_SAB_GET_INFO
	case SAB_GET_INFO_REQ:
		if (msg_type == MT_SAB_GET_INFO) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_GET_INFO,
						  prepare_msg_get_info,
						  proc_msg_rsp_get_info);
		}
		break;
#endif
	default:
		break;
	}

	return ret;
}

static int init_proc_sab_crrm_msg_engine(msg_type_t msg_type, uint32_t msg_id)
{
	int ret = NOT_DONE;

	switch (msg_id) {
#if MT_SAB_BOOT_MODE
	case SAB_CRRM_GET_BOOT_MODE_REQ:
		if (msg_type == MT_SAB_BOOT_MODE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_BOOT_MODE,
						  prepare_msg_get_boot_mode,
						  proc_msg_rsp_get_boot_mode);
		}
	break;
	case SAB_CRRM_SET_BOOT_MODE_REQ:
		if (msg_type == MT_SAB_BOOT_MODE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_BOOT_MODE,
						  prepare_msg_set_boot_mode,
						  proc_msg_rsp_set_boot_mode);
		}
	break;
#endif

#if MT_SAB_GET_AWDT_STATUS
	case SAB_CRRM_GET_STATUS_REQ:
		if (msg_type == MT_SAB_GET_AWDT_STATUS) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_GET_AWDT_STATUS,
						  prepare_msg_get_AWDT_status,
						  proc_msg_rsp_get_AWDT_status);
		}
	break;
#endif

#if MT_SAB_GET_NONCE
	case SAB_CRRM_GET_NONCE_REQ:
		if (msg_type == MT_SAB_GET_NONCE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_GET_NONCE,
						  prepare_msg_get_nonce,
						  proc_msg_rsp_get_nonce);
		}
	break;
#endif

#if MT_SAB_REFRESH_AWDT
	case SAB_CRRM_REFRESH_AWDT_REQ:
		if (msg_type == MT_SAB_REFRESH_AWDT) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_REFRESH_AWDT,
						  prepare_msg_refresh_AWDT,
						  proc_msg_rsp_refresh_AWDT);
		}
	break;
#endif
#if MT_SAB_DEV_GETINFO
	case ROM_DEV_GETINFO_REQ:
		if (msg_type == MT_SAB_DEV_GETINFO) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_DEV_GETINFO,
						  prepare_msg_dev_getinfo,
						  proc_msg_rsp_dev_getinfo);
		}
	break;
#endif
	default:
		break;
	}

	return ret;
}

void init_sab_crrm_msg_engine(msg_type_t msg_type)
{
	if (msg_type > NOT_SUPPORTED && msg_type >= MAX_MSG_TYPE)
		return;

	switch (msg_type) {
	case ROM_MSG:
		init_proc_sab_msg_cmd_eng(msg_type,
					  SAB_MSG_MAX_ID,
					  init_proc_sab_crrm_msg_engine);
		break;
	case SAB_MSG:
		init_proc_sab_msg_cmd_eng(msg_type, SAB_MSG_MAX_ID,
					  init_proc_sab_crrm_hsm_msg_engine);
			break;
	default:
		return;
	}
}
