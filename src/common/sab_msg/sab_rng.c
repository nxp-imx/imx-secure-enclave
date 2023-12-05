// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <string.h>

#include "common/rng.h"
#include <internal/she_rng.h>
#include "sab_rng.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

#ifndef PSA_COMPLIANT
uint32_t prepare_msg_extend_seed(void *phdl,
				 void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz,
				 uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl,
				 void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_extend_seed_msg *cmd =
		(struct sab_cmd_extend_seed_msg *)cmd_buf;
	op_rng_extend_seed_t *op_args = (op_rng_extend_seed_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->rng_handle = msg_hdl;
	set_phy_addr_to_words(cmd->entropy,
			      0u,
			      plat_os_abs_data_buf(phdl,
						   (uint8_t *)op_args->entropy,
						   op_args->entropy_size,
						   DATA_BUF_IS_INPUT));

	*cmd_msg_sz = sizeof(struct sab_cmd_extend_seed_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_extend_seed_rsp);

	return ret;
}

uint32_t proc_msg_rsp_extend_seed(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}
#endif

uint32_t prepare_msg_get_rng(void *phdl,
			     void *cmd_buf, void *rsp_buf,
			     uint32_t *cmd_msg_sz,
			     uint32_t *rsp_msg_sz,
			     uint32_t msg_hdl,
			     void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_get_rnd_msg *cmd =
		(struct sab_cmd_get_rnd_msg *) cmd_buf;
	op_get_random_args_t *op_args = (op_get_random_args_t *) args;

	if (!op_args)
		return SAB_ENGN_FAIL;

#ifdef PSA_COMPLIANT
	set_phy_addr_to_words(&cmd->rnd_addr,
			      &cmd->rnd_addr_msb,
			      plat_os_abs_data_buf(phdl,
						   op_args->output,
						   op_args->random_size,
						   DATA_BUF_IS_OUTPUT));
#else
	cmd->rng_handle = msg_hdl;
	set_phy_addr_to_words(&cmd->rnd_addr,
			      0u,
			      plat_os_abs_data_buf(phdl,
						   op_args->output,
						   op_args->random_size,
						   DATA_BUF_IS_OUTPUT));
#endif
	cmd->rnd_size = op_args->random_size;

	*cmd_msg_sz = sizeof(struct sab_cmd_get_rnd_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_get_rnd_rsp);

	return ret;
}

uint32_t proc_msg_rsp_get_rng(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}

#ifndef PSA_COMPLIANT
uint32_t prepare_msg_rng_open_req(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_rng_open_msg *cmd =
		(struct sab_cmd_rng_open_msg *) cmd_buf;
	struct sab_cmd_rng_open_rsp *rsp =
		(struct sab_cmd_rng_open_rsp *) rsp_buf;
	open_svc_rng_args_t *op_args = (open_svc_rng_args_t *) args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->session_handle = msg_hdl;
	cmd->input_address_ext = 0u;
	cmd->output_address_ext = 0u;
	cmd->flags = op_args->flags;
	cmd->pad[0] = 0u;
	cmd->pad[1] = 0u;
	cmd->pad[2] = 0u;

	cmd->crc = 0u;

	*cmd_msg_sz = sizeof(struct sab_cmd_rng_open_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_rng_open_rsp);

	return ret;
}

uint32_t proc_msg_rsp_rng_open_req(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_rng_open_rsp *rsp =
		(struct sab_cmd_rng_open_rsp *) rsp_buf;
	open_svc_rng_args_t *op_args = (open_svc_rng_args_t *) args;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		goto exit;
	}

	op_args->rng_hdl = rsp->rng_handle;
exit:
	return err;
}

uint32_t prepare_msg_rng_close_req(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
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
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}
#endif
