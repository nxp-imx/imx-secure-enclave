/*
 * Copyright 2019 NXP
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

#ifndef MESSAGING_H
#define MESSAGING_H

#include "stdint.h"

she_err_t she_seco_ind_to_she_err_t (uint32_t rsp_code);
int32_t she_send_msg_and_get_resp(struct she_platform_hdl *phdl, uint32_t *cmd, uint32_t cmd_len, uint32_t *rsp, uint32_t rsp_len);
uint32_t she_compute_msg_crc(uint32_t *msg, uint32_t msg_len);
she_err_t she_close_session_command (struct she_platform_hdl *phdl, uint32_t session_handle);
she_err_t she_get_shared_buffer(struct she_platform_hdl *phdl, uint32_t session_handle, uint32_t *shared_buf_offset, uint32_t *shared_buf_size);
she_err_t she_open_session_command (struct she_platform_hdl *phdl, uint32_t *session_handle, uint8_t mu_id, uint8_t interrupt_idx, uint8_t tz, uint8_t did, uint8_t priority,uint8_t operating_mode);
uint32_t sab_open_key_store_command(struct she_platform_hdl *phdl, uint32_t session_handle, uint32_t *key_store_handle, uint32_t key_storage_identifier, uint32_t password, uint16_t max_updates, uint8_t flags);
#define SHE_STORE_OPEN_FLAGS_CREATE     0x1u
#define SHE_STORE_OPEN_FLAGS_SHE        0x2u
uint32_t sab_close_key_store(struct she_platform_hdl *phdl, uint32_t key_store_handle);

#endif
