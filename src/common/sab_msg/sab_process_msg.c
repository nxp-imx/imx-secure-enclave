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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sab_process_msg.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

static bool init_done;

static uint32_t (*prepare_sab_msg[MAX_MSG_TYPE - 1][SAB_MSG_MAX_ID])
						(void *phdl, void *cmd_buf,
						 void *rsp_buf,
						 uint32_t *cmd_msg_sz,
						 uint32_t *rsp_msg_sz,
						 uint32_t msg_hdl,
						 void *args);

static uint32_t (*process_sab_msg_rsp[MAX_MSG_TYPE - 1][SAB_MSG_MAX_ID])
						(void *rsp_buf, void *args);




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
	int32_t error = 1;
	int msg_type_id;
	uint32_t cmd_msg_sz = 0;
	uint32_t rsp_msg_sz = 0;
	bool crc_added = false;
	uint32_t cmd[MAX_CMD_WORD_SZ];
	uint32_t rsp[MAX_CMD_RSP_WORD_SZ];

	if (init_done == false) {
		for (msg_type_id = ROM_MSG; msg_type_id < MAX_MSG_TYPE;
				msg_type_id++) {
			init_proc_sab_msg_engine(msg_type_id);
		}
		init_done = true;
	}

	plat_os_abs_memset((uint8_t *)cmd, 0x0, MAX_CMD_WORD_SZ * WORD_SZ);
	plat_os_abs_memset((uint8_t *)rsp, 0x0, MAX_CMD_RSP_WORD_SZ * WORD_SZ);

	if (msg_type <= NOT_SUPPORTED && msg_type >= MAX_MSG_TYPE) {
		error = SAB_INVALID_MESSAGE_RATING;
		goto out;
	}

	if (msg_id > SAB_MSG_MAX_ID) {
		error = SAB_NO_MESSAGE_RATING;
		goto out;
	}

	error = prepare_sab_msg[msg_type - 1][msg_id](phdl, &cmd, &rsp, &cmd_msg_sz,
					&rsp_msg_sz, msg_hdl, args);

	if ((error & SAB_MSG_CRC_BIT) == SAB_MSG_CRC_BIT) {
		crc_added = true;
	}

	plat_build_cmd_msg_hdr((struct sab_mu_hdr *)cmd, msg_type,
				msg_id, cmd_msg_sz, mu_type);

	if (crc_added == true) {
		plat_compute_msg_crc(cmd, (cmd_msg_sz - sizeof(uint32_t)));
	}

#ifdef DEBUG
	printf("\n---------- MSG Command with msg id[0x%x] = %d -------------\n", msg_id, msg_id);
	hexdump(cmd, cmd_msg_sz);
	printf("\n-------------------MSG END-----------------------------------\n");
#endif

	/* Send the message to platform. */
	error = plat_send_msg_and_get_resp(phdl,
		cmd, cmd_msg_sz, rsp, rsp_msg_sz);
	if (error) {
		goto out;
	}

#ifdef DEBUG
	printf("\n--------MSG Command response with msg id[0x%x] = %d ---------\n", msg_id, msg_id);
	hexdump(rsp, rsp_msg_sz);
	printf("\n-------------------MSG END-----------------------------------\n");
#endif

	*rsp_code = (*(rsp + 1));

	if (SAB_STATUS_SUCCESS(msg_type) == *rsp_code) {
		error = process_sab_msg_rsp[msg_type - 1][msg_id](&rsp, args);
	} else {
		printf("ERROR received SAB MSG CMD [0x%x] response[=0x%x]\n",
						msg_id, *rsp_code);
	}
out:
	return error;
}
