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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sab_common_err.h"
#include "sab_msg_def.h"
#include "sab_process_msg.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

static uint32_t (*prepare_sab_msg[MAX_MSG_TYPE - 1][SAB_MSG_MAX_ID])
						(void *phdl, void *cmd_buf,
						 void *rsp_buf,
						 uint32_t *cmd_msg_sz,
						 uint32_t *rsp_msg_sz,
						 uint32_t msg_hdl,
						 void *args);

static uint32_t (*process_sab_msg_rsp[MAX_MSG_TYPE - 1][SAB_MSG_MAX_ID])
						(void *rsp_buf, void *args);

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

sab_msg_init_info_t add_sab_msg_handler(uint32_t msg_id, msg_type_t msg_type,
			     uint32_t (*prep_sab_msg_handler)(void *phdl,
							      void *cmd_buf,
							      void *rsp_buf,
							      uint32_t *cmd_msg_sz,
							      uint32_t *rsp_msg_sz,
							      uint32_t msg_hdl,
							      void *args),
			     uint32_t (*proc_sab_msg_rsp_handler)(void *rsp_buf,
								  void *args))
{
	if (prepare_sab_msg[msg_type - 1][msg_id] != NULL)
		return ALREADY_DONE;

	prepare_sab_msg[msg_type - 1][msg_id] = prep_sab_msg_handler;
	process_sab_msg_rsp[msg_type - 1][msg_id] = proc_sab_msg_rsp_handler;

	return DONE;
}

void init_proc_sab_msg_cmd_eng(msg_type_t msg_type,
			       uint32_t max_msg_id,
			       int (*func)(msg_type_t msg_type, uint32_t msg_id))
{
	int i = 0;
	int ret = NOT_DONE;

	for (i = 0; i < max_msg_id; i++) {
		ret = NOT_DONE;

		ret = (func)(msg_type, i);
		if (ret == NOT_DONE) {
			add_sab_msg_handler(i, msg_type,
					    prep_sab_msg_not_supported,
					    proc_sab_msg_rsp_not_supported);
		}
	}
}

static void hexdump(uint32_t buf[], uint32_t size)
{
	int i = 0;

	for (; i < size; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%08x ", buf[i]);
	}
}

uint32_t process_sab_msg(struct plat_os_abs_hdl *phdl,
			 uint32_t mu_type,
			 uint8_t msg_id,
			 msg_type_t msg_type,
			 uint32_t msg_hdl,
			 void *args,
			 uint32_t *rsp_code)
{
	uint32_t error = SAB_SUCCESS_STATUS;
	int msg_type_id;
	uint32_t cmd_msg_sz = 0;
	uint32_t rsp_msg_sz = 0;
	bool cmd_crc_added = false;
	bool rsp_crc_expected = false;
	uint32_t cmd[MAX_CMD_WORD_SZ];
	uint32_t rsp[MAX_CMD_RSP_WORD_SZ];

	plat_os_abs_memset((uint8_t *)cmd, 0x0, MAX_CMD_WORD_SZ * WORD_SZ);
	plat_os_abs_memset((uint8_t *)rsp, 0x0, MAX_CMD_RSP_WORD_SZ * WORD_SZ);

	if (msg_type <= NOT_SUPPORTED && msg_type >= MAX_MSG_TYPE) {
		error = SAB_INVALID_MESSAGE_RATING;
		goto out;
	}

	if (msg_id == SAB_MSG_MAX_ID) {
		error = SAB_NO_MESSAGE_RATING;
		goto out;
	}

	if (prepare_sab_msg[msg_type - 1][msg_id] == NULL) {
		error = SAB_NO_MESSAGE_RATING;
		goto out;
	}

	error = prepare_sab_msg[msg_type - 1][msg_id](phdl, &cmd, &rsp, &cmd_msg_sz,
					&rsp_msg_sz, msg_hdl, args);

	if ((error & SAB_MSG_CRC_BIT) == SAB_MSG_CRC_BIT) {
		cmd_crc_added = true;
		/* strip-off the crc flag from error*/
		error &= ~SAB_MSG_CRC_BIT;
	}

	if ((error & SAB_RSP_CRC_BIT) == SAB_RSP_CRC_BIT) {
		rsp_crc_expected = true;
		/* strip-off the crc flag from error*/
		error &= ~SAB_RSP_CRC_BIT;
	}

	if (error) {
		error = SAB_NO_MESSAGE_RATING;
		goto out;
	}

	plat_build_cmd_msg_hdr((struct sab_mu_hdr *)cmd, msg_type,
				msg_id, cmd_msg_sz, mu_type);

	if (cmd_crc_added) {
		if (plat_add_msg_crc(cmd, cmd_msg_sz)) {
			error = SAB_NO_MESSAGE_RATING;
			goto out;
		}
	}

#ifdef DEBUG
	printf("\n---------- MSG Command with msg id[0x%x] = %d -------------\n", msg_id, msg_id);
	hexdump(cmd, cmd_msg_sz/sizeof(uint32_t));
	printf("\n-------------------MSG END-----------------------------------\n");
#endif

	/*
	 * Send the message to platform.
	 */
	error = plat_send_msg_and_rcv_resp(phdl,
		cmd, cmd_msg_sz, rsp, &rsp_msg_sz);
	if (error) {
		error = SAB_NO_MESSAGE_RATING;
		goto out;
	}

	if (rsp_crc_expected) {
		if (plat_validate_msg_crc(rsp, rsp_msg_sz)) {
			error = SAB_NO_MESSAGE_RATING;
			goto out;
		}
	}

#ifdef DEBUG
	printf("\n--------MSG Command response with msg id[0x%x] = %d ---------\n", msg_id, msg_id);
	hexdump(rsp, rsp_msg_sz/sizeof(uint32_t));
	printf("\n-------------------MSG END-----------------------------------\n");
#endif

	*rsp_code = (*(rsp + 1));

	if (SAB_STATUS_SUCCESS(msg_type) != *rsp_code)
		sab_err_map(msg_id, *rsp_code);

	if (process_sab_msg_rsp[msg_type - 1][msg_id] == NULL) {
		error = SAB_NO_MESSAGE_RATING;
		goto out;
	}

	error = process_sab_msg_rsp[msg_type - 1][msg_id](&rsp, args);
out:
	return error;
}

static uint32_t (*prepare_sab_rcvmsg_rsp[SAB_RCVMSG_MAX_ID])
						(struct nvm_ctx_st *nvm_param,
						 void *cmd_buf,
						 void *rsp_buf,
						 uint32_t *cmd_msg_sz,
						 uint32_t *rsp_msg_sz,
						 void **data,
						 uint32_t *data_sz,
						 uint8_t *prev_cmd_id,
						 uint8_t *next_cmd_id);

static uint32_t parse_cmd_prep_rsp_msg_not_supported(struct nvm_ctx_st *nvm_param,
						    void *cmd_buf, void *rsp_buf,
						    uint32_t *cmd_msg_sz,
						    uint32_t *rsp_msg_sz,
						    void **data, uint32_t *data_sz,
						    uint8_t *prev_cmd_id,
						    uint8_t *next_cmd_id)
{
	printf("Error: CMD not supported.\n");
	return SAB_CMD_NOT_SUPPORTED_RATING;
}

sab_msg_init_info_t add_sab_rcvmsg_handler(uint32_t msg_id, msg_type_t msg_type,
					   uint32_t (*prep_sab_rcvmsg_rsp_handler)
								(struct nvm_ctx_st *nvm_param,
								 void *cmd_buf,
								 void *rsp_buf,
								 uint32_t *cmd_msg_sz,
								 uint32_t *rsp_msg_sz,
								 void **data,
								 uint32_t *data_sz,
								 uint8_t *prev_cmd_id,
								 uint8_t *next_cmd_id))
{
	/* msg_id offset is set by the caller, after
	 * doing the subtraction of SAB_RCVMSG_START_ID.
	 */
	if (prepare_sab_rcvmsg_rsp[msg_id] != NULL)
		return ALREADY_DONE;

	prepare_sab_rcvmsg_rsp[msg_id] = prep_sab_rcvmsg_rsp_handler;

	return DONE;
}

void init_proc_sab_msg_rcv_eng(msg_type_t msg_type,
			       uint32_t start_msg_id,
			       uint32_t max_msg_id,
			       int (*func)(msg_type_t msg_type,
					   uint32_t start_msg_id,
					   uint32_t msg_id))
{
	int i = 0;
	int ret = NOT_DONE;

	if (max_msg_id < start_msg_id) {
		se_err("Initialization Failure(Range-mismatch).\n");
		return;
	}

	for (i = 0; i < (max_msg_id - start_msg_id); i++) {
		ret = NOT_DONE;

		ret = (func)(msg_type, start_msg_id, (start_msg_id + i));
		if (ret == NOT_DONE) {
			add_sab_rcvmsg_handler(i, msg_type,
					       parse_cmd_prep_rsp_msg_not_supported);
		}
	}
}

uint32_t process_sab_rcv_send_msg(struct nvm_ctx_st *nvm_ctx_param,
				  void **data,
				  uint32_t *data_sz,
				  uint8_t *prev_cmd_id,
				  uint8_t *next_cmd_id)
{
	int error = SAB_SUCCESS_STATUS;
	int msg_type_id;
	uint32_t rcvmsg_cmd_id;
	uint32_t cmd_msg_sz = MAX_CMD_WORD_SZ * sizeof(uint32_t);
	uint32_t rsp_msg_sz = 0;
	bool rsp_crc_added = false;
	uint32_t cmd[MAX_CMD_WORD_SZ];
	uint32_t rsp[MAX_CMD_RSP_WORD_SZ];
	uint32_t cmd_args[MAX_CMD_RSP_WORD_SZ];
	msg_type_t msg_type = SAB_MSG;
	struct nvm_chunk_hdr *chunk = NULL;

	chunk = *data;

	plat_os_abs_memset((uint8_t *)cmd, 0x0, MAX_CMD_WORD_SZ * WORD_SZ);
	plat_os_abs_memset((uint8_t *)rsp, 0x0, MAX_CMD_RSP_WORD_SZ * WORD_SZ);

	error = plat_rcvmsg_cmd(nvm_ctx_param->phdl, cmd, &cmd_msg_sz, &rcvmsg_cmd_id);

	if (error) {
		printf("Error in receiving cmd from FW.\n");
		error = (error < 0) ? SAB_READ_FAILURE_RATING
					: SAB_NO_MESSAGE_RATING;
		goto out;
	}

	if (rcvmsg_cmd_id >= SAB_STORAGE_NVM_LAST_CMD ||
	    rcvmsg_cmd_id < SAB_RCVMSG_START_ID) {
		error = SAB_NO_MESSAGE_RATING;

		printf("Un-Supported Messsage ID [0x%x].\n", rcvmsg_cmd_id);
		goto out;
	}

	if ((*next_cmd_id != NEXT_EXPECTED_CMD_NONE)
			&& (rcvmsg_cmd_id != *next_cmd_id)) {
		if (*data != NULL) {
			if (chunk->data)
				plat_os_abs_free(chunk->data);
			plat_os_abs_free(*data);
			*data_sz = 0;
		}
		*next_cmd_id = NEXT_EXPECTED_CMD_NONE;
		printf("Expected Command ID mismatch:\n");
		printf("\tExpected CMD = 0x%x, while Received CMD = 0x%x\n",
							*next_cmd_id,
							rcvmsg_cmd_id);
		error = SAB_NO_MESSAGE_RATING;
		goto out;
	}

	/* parse command prepare response */
	error = prepare_sab_rcvmsg_rsp[rcvmsg_cmd_id - SAB_RCVMSG_START_ID]
							(nvm_ctx_param,
							 &cmd,
							 &rsp,
							 &cmd_msg_sz,
							 &rsp_msg_sz,
							 data,
							 data_sz,
							 prev_cmd_id,
							 next_cmd_id);

	if ((error & SAB_MSG_CRC_BIT) == SAB_MSG_CRC_BIT) {
		/* strip-off the crc flag from error*/
		error &= ~SAB_MSG_CRC_BIT;
		if (plat_validate_msg_crc(cmd, cmd_msg_sz)) {
			error = SAB_NO_MESSAGE_RATING;
			goto out;
		}
	}

	if ((error & SAB_RSP_CRC_BIT) == SAB_RSP_CRC_BIT) {
		rsp_crc_added = true;
		/* strip-off the crc flag from error*/
		error &= ~SAB_RSP_CRC_BIT;
	}

	if (error != SAB_SUCCESS_STATUS) {
		error = SAB_NO_MESSAGE_RATING;
		goto out;
	}

	plat_build_rsp_msg_hdr((struct sab_mu_hdr *)rsp, msg_type,
				rcvmsg_cmd_id,
				rsp_msg_sz, nvm_ctx_param->mu_type);

	if (rsp_crc_added) {
		if (plat_add_msg_crc(rsp, rsp_msg_sz)) {
			error = SAB_NO_MESSAGE_RATING;
			goto out;
		}
	}

	error = plat_sndmsg_rsp(nvm_ctx_param->phdl, rsp, rsp_msg_sz);
	if (error) {
		printf("Error sending command[0x%x] response.\n",
							rcvmsg_cmd_id);
		error = SAB_NO_MESSAGE_RATING;
		goto out;
	}

	if (*next_cmd_id == NEXT_EXPECTED_CMD_NONE) {
		if (*data != NULL) {
			if (*prev_cmd_id == SAB_STORAGE_CHUNK_EXPORT_REQ) {
				if (chunk->data)
					plat_os_abs_free(chunk->data);
			}
			plat_os_abs_free(*data);
			*data_sz = 0;
		}
	}

out:
	return error;
}
