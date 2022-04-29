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


#ifndef SAB_PROCESS_MSG_H
#define SAB_PROCESS_MSG_H

#include <stdint.h>
#include "plat_os_abs.h"
#include "plat_utils.h"

#define MAX_CMD_SZ	1024
#define MAX_CMD_RSP_SZ	1024

typedef enum {
	NOT_DONE,
	DONE,
	ALREADY_DONE
} sab_msg_init_info_t;

sab_msg_init_info_t add_sab_msg_handler(uint32_t msg_id, msg_type_t msg_type,
			     uint32_t (*prep_sab_msg_handler)(void *phdl,
							      void *cmd_buf,
							      void *rsp_buf,
							      uint32_t *cmd_msg_sz,
							      uint32_t *rsp_msg_sz,
							      uint32_t msg_hdl,
							      void *args),
			     uint32_t (*proc_sab_msg_rsp_handler)(void *rsp_buf,
								  void *args));

uint32_t process_sab_msg(struct plat_os_abs_hdl *phdl,
			 uint32_t mu_type,
			 uint8_t msg_id,
			 msg_type_t msg_type,
			 uint32_t msg_hdl,
			 void *args,
			 uint32_t *rsp_code);

void init_proc_sab_msg_engine(msg_type_t msg_type);
#endif
