/*
 * Copyright 2022 NXP
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

#if MT_SAB_DEBUG_DUMP
#include "sab_debug_dump.h"
#endif

#if MT_SAB_KEY_GENERATE
#include "sab_key_generate.h"
#endif

#if MT_SAB_KEY_GEN_EXT
#include "sab_key_gen_ext.h"
#endif

#if MT_SAB_MANAGE_KEY
#include "sab_managekey.h"
#endif

static uint32_t prep_sab_msg_not_supported(void *phdl, void *cmd_buf,
					   void *rsp_buf, uint32_t *cmd_msg_sz,
					   uint32_t *rsp_msg_sz,
					   uint32_t msg_hdl, void *args)
{
	printf("Error: CMD not supported.\n");
	return SAB_CMD_NOT_SUPPORTED_RATING;
}

static uint32_t proc_sab_msg_rsp_not_supported(void *rsp_buf, void *args)
{
	return SAB_CMD_NOT_SUPPORTED_RATING;
}


void init_proc_sab_msg_engine(msg_type_t msg_type)
{
	int i = 0;
	int ret = NOT_DONE;

	for (i = 0; i < SAB_MSG_MAX_ID; i++) {
		ret = NOT_DONE;

		switch (i) {
#if MT_SAB_DEBUG_DUMP
		case ROM_DEBUG_DUMP_REQ:
			if (msg_type == MT_SAB_DEBUG_DUMP) {
				ret = add_sab_msg_handler(i, MT_SAB_DEBUG_DUMP,
						  prepare_msg_debugdump,
						  proc_msg_rsp_debugdump);
			}
		break;
#endif
#if MT_SAB_KEY_GENERATE
		case SAB_KEY_GENERATE_REQ:
			if (msg_type == MT_SAB_KEY_GENERATE) {
				ret = add_sab_msg_handler(i, MT_SAB_KEY_GENERATE,
						  prepare_msg_generatekey,
						  proc_msg_rsp_generatekey);
			}
		break;
#endif
#if MT_SAB_KEY_GEN_EXT
		case SAB_KEY_GENERATE_EXT_REQ:
			if (msg_type == MT_SAB_KEY_GEN_EXT) {
				ret = add_sab_msg_handler(i, MT_SAB_KEY_GEN_EXT,
						  prepare_msg_gen_key_ext,
						  proc_msg_rsp_gen_key_ext);
			}
		break;
#endif
#if MT_SAB_MANAGE_KEY
		case SAB_MANAGE_KEY_REQ:
			if (msg_type == MT_SAB_MANAGE_KEY) {
				ret = add_sab_msg_handler(i, MT_SAB_MANAGE_KEY,
						  prepare_msg_managekey,
						  proc_msg_rsp_managekey);
			}
		break;
		case SAB_MANAGE_KEY_EXT_REQ:
			if (msg_type == MT_SAB_MANAGE_KEY) {
				ret = add_sab_msg_handler(i, MT_SAB_MANAGE_KEY,
						  prepare_msg_managekey_ext,
						  proc_msg_rsp_managekey);
			}
		break;
#endif
		default:
			if (ret == NOT_DONE) {
				add_sab_msg_handler(i, SAB_MSG,
						prep_sab_msg_not_supported,
						proc_sab_msg_rsp_not_supported);
			}
		}

	}
}
