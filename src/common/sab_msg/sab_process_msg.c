// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdlib.h>
#include <stdio.h>

#include "sab_common_err.h"
#include "sab_msg_def.h"
#include "sab_process_msg.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

static struct eng_op ep = {
	.cancel_signal = 0
};

void send_cancel_signal_to_engine(void)
{
	ep.cancel_signal = 1;
}

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
	return SAB_LIB_STATUS(SAB_LIB_CMD_UNSUPPORTED);
}

static uint32_t proc_sab_msg_rsp_not_supported(void *rsp_buf, void *args)
{
	return SAB_LIB_STATUS(SAB_LIB_CMD_UNSUPPORTED);
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

#ifdef DEBUG
static void hexdump(uint32_t buf[], uint32_t size)
{
	int i = 0;

	for (; i < size; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%08x ", buf[i]);
	}
}
#endif

static uint8_t err_handling_v2_support(uint8_t msg_id)
{
	uint8_t ret = 0;

	if (msg_id == SAB_SESSION_OPEN_REQ ||
	    msg_id == SAB_SESSION_CLOSE_REQ ||
	    msg_id == ROM_DEV_GETINFO_REQ ||
	    msg_id == SAB_SHE_FAST_MAC_MUBUFF_REQ ||
	    msg_id == SAB_BUT_KEY_EXP_REQ ||
	    msg_id == SAB_PUB_KEY_DECOMPRESSION_REQ ||
	    msg_id == SAB_ROOT_KEK_EXPORT_REQ ||
	    msg_id == SAB_PUB_KEY_RECONSTRUCTION_REQ ||
	    msg_id == SAB_TLS_FINISH_REQ ||
	    msg_id == SAB_FAST_MAC_REQ)
		ret = 1;

	return ret;
}

uint32_t process_sab_msg(struct plat_os_abs_hdl *phdl,
			 uint32_t mu_type,
			 uint8_t msg_id,
			 msg_type_t msg_type,
			 uint32_t msg_hdl,
			 void *args,
			 uint32_t *rsp_code)
{
	uint32_t error;
	uint32_t cmd_msg_sz = 0;
	uint32_t rsp_msg_sz = 0;
	uint32_t cmd[MAX_CMD_WORD_SZ];
	uint32_t rsp[MAX_CMD_RSP_WORD_SZ];
	uint32_t nb_words = 0;

	plat_os_abs_memset((uint8_t *)cmd, 0x0, MAX_CMD_WORD_SZ * WORD_SZ);
	plat_os_abs_memset((uint8_t *)rsp, 0x0, MAX_CMD_RSP_WORD_SZ * WORD_SZ);

	/**
	 * Check if CMD is valid or not, i.e.
	 *	-MSG Type value is in valid range
	 *	-MSG ID is in valid range
	 */
	if (msg_type <= NOT_SUPPORTED || msg_type >= MAX_MSG_TYPE) {
		if (err_handling_v2_support(msg_id))
			error = SENDMSG_ENGN_ERR(SAB_LIB_CMD_INVALID);
		else
			error = SAB_INVALID_MESSAGE_RATING;

		goto out;
	}

	if (msg_id == SAB_MSG_MAX_ID) {
		if (err_handling_v2_support(msg_id))
			error = SENDMSG_ENGN_ERR(SAB_LIB_CMD_INVALID);
		else
			error = SAB_NO_MESSAGE_RATING;

		goto out;
	}

	/**
	 * Check if some valid function pointer for preparing CMD msg
	 * has been mapped.
	 *
	 * Before accessing the function, through function pointer mapped, NULL
	 * check is important.
	 */
	if (prepare_sab_msg[msg_type - 1][msg_id] == NULL) {
		if (err_handling_v2_support(msg_id))
			error = SENDMSG_ENGN_ERR(SAB_LIB_INVALID_MSG_HANDLER);
		else
			error = SAB_NO_MESSAGE_RATING;

		goto out;
	}

	error = prepare_sab_msg[msg_type - 1][msg_id](phdl, &cmd, &rsp, &cmd_msg_sz,
					&rsp_msg_sz, msg_hdl, args);

	if (err_handling_v2_support(msg_id)) {
		if (PARSE_LIB_ERR_STATUS(error) != SAB_LIB_SUCCESS) {
			error = ENGN_SEND_CMD_PATH_FLAG | error;
			goto out;
		}

	} else {
		if (error) {
			error = SAB_NO_MESSAGE_RATING;
			goto out;
		}
	}

	plat_build_cmd_msg_hdr((struct sab_mu_hdr *)cmd, msg_type,
				msg_id, cmd_msg_sz, mu_type);

	/* Add CRC in cmd if needed */
	nb_words = cmd_msg_sz / (uint32_t)sizeof(uint32_t);
	if (nb_words > SAB_STORAGE_NB_WORDS_MAX_WO_CRC) {
		if (plat_add_msg_crc(cmd, cmd_msg_sz)) {
			if (err_handling_v2_support(msg_id))
				error = SENDMSG_ENGN_ERR(SAB_LIB_CRC_FAIL);
			else
				error = SAB_NO_MESSAGE_RATING;

			goto out;
		}
	}

	if (ep.cancel_signal) {
		ep.cancel_signal = 0;

		if (err_handling_v2_support(msg_id)) {
			error = SAB_LIB_SHE_CANCEL_ERROR;
			goto out;
		}

		return SAB_SHE_GENERAL_ERROR_RATING;
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
		if (err_handling_v2_support(msg_id))
			error = RCVMSG_ENGN_ERR(SAB_LIB_CMD_RSP_TRANSACT_FAIL);
		else
			error = SAB_NO_MESSAGE_RATING;

		goto out;
	}

	if (ep.cancel_signal) {
		ep.cancel_signal = 0;

		if (err_handling_v2_support(msg_id)) {
			error = SAB_LIB_SHE_CANCEL_ERROR;
			goto out;
		}

		return SAB_SHE_GENERAL_ERROR_RATING;
	}

	/* Add CRC in response if needed */
	nb_words = rsp_msg_sz / (uint32_t)sizeof(uint32_t);
	if (nb_words > SAB_STORAGE_NB_WORDS_MAX_WO_CRC) {
		if (plat_validate_msg_crc(rsp, rsp_msg_sz)) {
			if (err_handling_v2_support(msg_id))
				error = RCVMSG_ENGN_ERR(SAB_LIB_CRC_FAIL);
			else
				error = SAB_NO_MESSAGE_RATING;

			goto out;
		}
	}

#ifdef DEBUG
	printf("\n--------MSG Command response with msg id[0x%x] = %d ---------\n", msg_id, msg_id);
	hexdump(rsp, rsp_msg_sz/sizeof(uint32_t));
	printf("\n-------------------MSG END-----------------------------------\n");
#endif

	/**
	 * Assigning API response code received from FW
	 */
	*rsp_code = (*(rsp + 1));

	/* Debug prints for any case other than success.
	 * - print error.
	 * - print waring with success.
	 */
	if (SAB_STATUS_SUCCESS(msg_type) != GET_STATUS_CODE(*rsp_code) ||
	    GET_RATING_CODE(*rsp_code) != SAB_NO_MESSAGE_RATING)
		sab_err_map(msg_type, msg_id, *rsp_code);

	if (process_sab_msg_rsp[msg_type - 1][msg_id] == NULL) {
		if (err_handling_v2_support(msg_id))
			error = RCVMSG_ENGN_ERR(SAB_LIB_INVALID_MSG_HANDLER);
		else
			error = SAB_NO_MESSAGE_RATING;

		goto out;
	}

	error = process_sab_msg_rsp[msg_type - 1][msg_id](&rsp, args);

	if (err_handling_v2_support(msg_id)) {
		if (PARSE_LIB_ERR_STATUS(error) != SAB_LIB_SUCCESS) {
			error = ENGN_RCV_RESP_PATH_FLAG | error;
			goto out;
		}
	} else {
		/**
		 * For the APIs not yet supporting new error handling approach,
		 * still the previous/same SAB error code needs to be returned.
		 * Handling the case of SAB_CMD_NOT_SUPPORTED_RATING here.
		 */
		if (error == SAB_LIB_CMD_UNSUPPORTED)
			error = SAB_CMD_NOT_SUPPORTED_RATING;
	}

	/**
	 * Returning Library Success code if reached till here.
	 */
	if (err_handling_v2_support(msg_id))
		error = RCVMSG_ENGN_ERR(SAB_LIB_SUCCESS);
out:
	/**
	 * printing Plat errors and Library errors if occurred.
	 */
	if (err_handling_v2_support(msg_id) &&
	    PARSE_LIB_ERR_STATUS(error) != SAB_LIB_SUCCESS) {
		se_err("LIB Error: CMD [0x%x] error [0x%06x]\n", msg_id, error);
		plat_lib_err_map(msg_id, PARSE_LIB_ERR_PLAT(error));
		sab_lib_err_map(msg_id, PARSE_LIB_ERR_STATUS(error));
	}

	return error;
}

/*
 * @rsp_msg_info is a in/out parameter:
 *     [in]: if set, it represents a response error code to send.
 *     [out]: it represents the response size in bytes.
 */
static uint32_t (*prepare_sab_rcvmsg_rsp[SAB_RCVMSG_MAX_ID])
						(struct nvm_ctx_st *nvm_param,
						 void *cmd_buf,
						 void *rsp_buf,
						 uint32_t *cmd_msg_sz,
						 uint32_t *rsp_msg_info,
						 void **data,
						 uint32_t *data_sz,
						 uint8_t *prev_cmd_id,
						 uint8_t *next_cmd_id);

static uint32_t parse_cmd_prep_rsp_msg_not_supported(struct nvm_ctx_st *nvm_param,
						    void *cmd_buf, void *rsp_buf,
						    uint32_t *cmd_msg_sz,
						    uint32_t *rsp_msg_info,
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
								 uint32_t *rsp_msg_info,
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
	uint32_t error;
	uint32_t rcvmsg_cmd_id = SAB_STORAGE_NVM_LAST_CMD;
	uint32_t cmd_msg_sz = MAX_CMD_WORD_SZ * sizeof(uint32_t);
	uint32_t rsp_msg_info = SAB_SUCCESS_STATUS;
	uint32_t nb_words = 0;
	uint32_t cmd[MAX_CMD_WORD_SZ];
	uint32_t rsp[MAX_CMD_RSP_WORD_SZ];
	msg_type_t msg_type = SAB_MSG;
	struct nvm_chunk_hdr *chunk = NULL;

	chunk = *data;

	plat_os_abs_memset((uint8_t *)cmd, 0x0, sizeof(cmd));
	plat_os_abs_memset((uint8_t *)rsp, 0x0, sizeof(rsp));

	error = plat_rcvmsg_cmd(nvm_ctx_param->phdl, cmd, &cmd_msg_sz, &rcvmsg_cmd_id);

	if (error) {
		printf("Error in receiving cmd from FW.\n");
		error = (error == PLAT_FAILURE) ? SAB_READ_FAILURE_RATING
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
			/* Set data pointer to NULL to prevent double free */
			*data = NULL;
			*data_sz = 0;
		}
		*next_cmd_id = NEXT_EXPECTED_CMD_NONE;
		printf("Expected Command ID mismatch:\n");
		printf("\tExpected CMD = 0x%x, while Received CMD = 0x%x\n",
							*next_cmd_id,
							rcvmsg_cmd_id);
		/* Send error to FW through the command response */
		rsp_msg_info = SAB_INVALID_MSG_STATUS;
	} else {
		nb_words = cmd_msg_sz / (uint32_t)sizeof(uint32_t);
		if (nb_words > SAB_STORAGE_NB_WORDS_MAX_WO_CRC &&
		    plat_validate_msg_crc(cmd, cmd_msg_sz) == 1) {
#ifdef PSA_COMPLIANT
			/* Send error to FW through the command response */
			rsp_msg_info = SAB_CRC_FAILURE_STATUS;
#else
			rsp_msg_info = SAB_SUCCESS_STATUS;
#endif
		} else {
			rsp_msg_info = SAB_SUCCESS_STATUS;
		}
	}

	/*
	 * parse command prepare response. If @rsp_msg_info is set
	 * (!= SAB_SUCCESS_STATUS) do not execute operation and send error to FW.
	 * Function returns rsp msg size in @rsp_msg_info variable.
	 */
	error = prepare_sab_rcvmsg_rsp[rcvmsg_cmd_id - SAB_RCVMSG_START_ID]
							(nvm_ctx_param,
							 &cmd,
							 &rsp,
							 &cmd_msg_sz,
							 &rsp_msg_info,
							 data,
							 data_sz,
							 prev_cmd_id,
							 next_cmd_id);

	if (rsp_msg_info > MAX_CMD_RSP_WORD_SZ) {
		/* Exit with failure if response is too big for rsp buffer. (Should not happened) */
		se_err("Error: Response size is too big: %d\n", rsp_msg_info);
		error = SAB_FAILURE_STATUS;
		goto out;
	}

	if (error != SAB_SUCCESS_STATUS)
		se_warn("Warn: command 0x%x failed with 0x%x error code.\n", rcvmsg_cmd_id, error);

	plat_build_rsp_msg_hdr((struct sab_mu_hdr *)rsp, msg_type,
				rcvmsg_cmd_id,
				rsp_msg_info, nvm_ctx_param->mu_type);

	/* Add CRC in response if needed */
	nb_words = rsp_msg_info / (uint32_t)sizeof(uint32_t);
	if (nb_words > SAB_STORAGE_NB_WORDS_MAX_WO_CRC) {
		/* Add msg crc function never failed */
		(void)plat_add_msg_crc(rsp, rsp_msg_info);
	}

	error = plat_sndmsg_rsp(nvm_ctx_param->phdl, rsp, rsp_msg_info);
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
			/* Set data pointer to NULL to prevent double free */
			*data = NULL;
			*data_sz = 0;
		}
	}

out:
	return error;
}
