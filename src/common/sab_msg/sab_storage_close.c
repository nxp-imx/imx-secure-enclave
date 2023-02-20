/*
 * Copyright 2023 NXP
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

#include <errno.h>
#include <stdint.h>

#include "sab_storage_close.h"
#include "sab_nvm.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_storage_close(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_storage_close_msg *msg =
		(struct sab_cmd_storage_close_msg *)cmd_buf;
	struct sab_cmd_storage_close_rsp *rsp =
		(struct sab_cmd_storage_close_rsp *)rsp_buf;

	msg->storage_handle = msg_hdl;

	*cmd_msg_sz = sizeof(struct sab_cmd_storage_close_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_storage_close_rsp);

	return ret;
}

uint32_t proc_msg_rsp_storage_close(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}
