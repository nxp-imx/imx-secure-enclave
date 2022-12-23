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

#include <string.h>

#include "internal/hsm_rng.h"
#include "sab_rng.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_get_rng(void *phdl,
			     void *cmd_buf, void *rsp_buf,
			     uint32_t *cmd_msg_sz,
			     uint32_t *rsp_msg_sz,
			     uint32_t msg_hdl,
			     void *args)
{
	int32_t ret = 0;
	struct sab_cmd_get_rnd_msg *cmd =
		(struct sab_cmd_get_rnd_msg *) cmd_buf;
	struct sab_cmd_get_rnd_rsp *rsp =
		(struct sab_cmd_get_rnd_rsp *) rsp_buf;
	op_get_random_args_t *op_args = (op_get_random_args_t *) args;
	uint64_t rnd_addr = 0;

	rnd_addr = plat_os_abs_data_buf(phdl,
				op_args->output,
				op_args->random_size,
				DATA_BUF_IS_OUTPUT);

#ifdef PSA_COMPLIANT
	cmd->rnd_addr = (uint32_t) rnd_addr;
	cmd->rnd_addr_msb = (uint32_t) (rnd_addr >> 32);
#else
	cmd->rng_handle = msg_hdl;
	cmd->rnd_addr = (uint32_t) rnd_addr;
#endif
	cmd->rnd_size = op_args->random_size;

	*cmd_msg_sz = sizeof(struct sab_cmd_get_rnd_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_get_rnd_rsp);

	return ret;
}

uint32_t proc_msg_rsp_get_rng(void *rsp_buf, void *args)
{
	struct sab_cmd_get_rnd_rsp *rsp =
		(struct sab_cmd_get_rnd_rsp *) rsp_buf;

	return SAB_SUCCESS_STATUS;
}

#ifndef PSA_COMPLIANT
uint32_t prepare_msg_rng_open_req(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_rng_open_msg *cmd =
		(struct sab_cmd_rng_open_msg *) cmd_buf;
	struct sab_cmd_rng_open_rsp *rsp =
		(struct sab_cmd_rng_open_rsp *) rsp_buf;
	open_svc_rng_args_t *op_args = (open_svc_rng_args_t *) args;

	cmd->session_handle = msg_hdl;
	cmd->input_address_ext = 0u;
	cmd->output_address_ext = 0u;
	cmd->flags = op_args->flags;
	cmd->pad[0] = 0u;
	cmd->pad[1] = 0u;
	cmd->pad[2] = 0u;

	cmd->crc = 0u;
	ret |= SAB_MSG_CRC_BIT;

	*cmd_msg_sz = sizeof(struct sab_cmd_rng_open_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_rng_open_rsp);

	return ret;
}

uint32_t proc_msg_rsp_rng_open_req(void *rsp_buf, void *args)
{
	struct sab_cmd_rng_open_rsp *rsp =
		(struct sab_cmd_rng_open_rsp *) rsp_buf;
	open_svc_rng_args_t *op_args = (open_svc_rng_args_t *) args;

	op_args->rng_hdl = rsp->rng_handle;

	return SAB_SUCCESS_STATUS;
}

uint32_t prepare_msg_rng_close_req(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_rng_close_msg *cmd =
		(struct sab_cmd_rng_close_msg *) cmd_buf;
	struct sab_cmd_rng_close_rsp *rsp =
		(struct sab_cmd_rng_close_rsp *) rsp_buf;

	*cmd_msg_sz = sizeof(struct sab_cmd_rng_close_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_rng_close_rsp);

	cmd->rng_handle = msg_hdl;

	return ret;
}

uint32_t proc_msg_rsp_rng_close_req(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}
#endif
