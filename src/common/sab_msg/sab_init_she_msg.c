// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "sab_msg_def.h"
#include "sab_process_msg.h"

#if MT_SAB_SESSION
#include "sab_session.h"
#endif

#if MT_SAB_GET_INFO
#include "sab_get_info.h"
#endif

#if MT_SAB_SHARED_BUF
#include "sab_shared_buf.h"
#endif

#if MT_SAB_KEY_STORE
#include "sab_key_store.h"
#endif

#if MT_SAB_UTILS
#include "sab_utils_service.h"
#endif

#if MT_SAB_CIPHER
#include "sab_cipher.h"
#endif

#if MT_SAB_GET_STATUS
#include "sab_get_status.h"
#endif

#if MT_SAB_RNG
#include "sab_rng.h"
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
#if MT_SAB_GET_INFO
	case SAB_GET_INFO_REQ:
		if (msg_type == MT_SAB_GET_INFO) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_GET_INFO,
						  prepare_msg_get_info,
						  proc_msg_rsp_get_info);
		}
		break;
#endif
#if MT_SAB_SHARED_BUF
	case SAB_SHARED_BUF_REQ:
		if (msg_type == MT_SAB_SHARED_BUF) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_SHARED_BUF,
						  prepare_msg_shared_buf,
						  proc_msg_rsp_shared_buf);
		}
		break;
#endif
#if MT_SAB_KEY_STORE
	case SAB_KEY_STORE_OPEN_REQ:
		if (msg_type == MT_SAB_KEY_STORE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_KEY_STORE,
						  prepare_msg_key_store_open_req,
						  proc_msg_rsp_key_store_open_req);
		}
		break;
	case SAB_KEY_STORE_CLOSE_REQ:
		if (msg_type == MT_SAB_KEY_STORE) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_KEY_STORE,
						  prepare_msg_key_store_close_req,
						  proc_msg_rsp_key_store_close_req);
		}
		break;
#endif
#if MT_SAB_UTILS
	case SAB_SHE_UTILS_OPEN:
		if (msg_type == MT_SAB_UTILS) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_UTILS,
						  prepare_msg_open_utils,
						  proc_msg_rsp_open_utils);
		}
		break;
	case SAB_SHE_UTILS_CLOSE:
		if (msg_type == MT_SAB_UTILS) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_UTILS,
						  prepare_msg_close_utils,
						  proc_msg_rsp_close_utils);
		}
		break;
#endif
#if MT_SAB_CIPHER
	case SAB_CIPHER_OPEN_REQ:
		if (msg_type == MT_SAB_CIPHER) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_CIPHER,
						  prepare_msg_cipher_open_req,
						  proc_msg_rsp_cipher_open_req);
		}
		break;
	case SAB_CIPHER_CLOSE_REQ:
		if (msg_type == MT_SAB_CIPHER) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_CIPHER,
						  prepare_msg_cipher_close_req,
						  proc_msg_rsp_cipher_close_req);
		}
		break;
#endif
#if MT_SAB_GET_STATUS
	case SAB_SHE_GET_STATUS:
		if (msg_type == MT_SAB_GET_STATUS) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_GET_STATUS,
						  prepare_msg_get_status,
						  proc_msg_rsp_get_status);
		}
		break;
#endif
#if MT_SAB_RNG
#ifndef PSA_COMPLIANT
	case SAB_RNG_OPEN_REQ:
		if (msg_type == MT_SAB_RNG) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_RNG,
						  prepare_msg_rng_open_req,
						  proc_msg_rsp_rng_open_req);
		}
		break;
	case SAB_RNG_CLOSE_REQ:
		if (msg_type == MT_SAB_RNG) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_RNG,
						  prepare_msg_rng_close_req,
						  proc_msg_rsp_rng_close_req);
		}
		break;
	case SAB_RNG_EXTEND_SEED:
		if (msg_type == MT_SAB_RNG) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_RNG,
						  prepare_msg_extend_seed,
						  proc_msg_rsp_extend_seed);
		}
		break;
#endif
	case SAB_RNG_GET_RANDOM:
		if (msg_type == MT_SAB_RNG) {
			ret = add_sab_msg_handler(msg_id, MT_SAB_RNG,
						  prepare_msg_get_rng,
						  proc_msg_rsp_get_rng);
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
