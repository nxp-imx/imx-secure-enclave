#ifndef MESSAGING_H
#define MESSAGING_H

#include "stdint.h"

she_err_t she_seco_ind_to_she_err_t (uint32_t rsp_code);
int32_t she_send_msg_and_get_resp(struct she_platform_hdl *phdl, uint32_t *cmd, uint32_t cmd_len, uint32_t *rsp, uint32_t rsp_len);
uint32_t she_compute_msg_crc(uint32_t *msg, uint32_t msg_len);
she_err_t she_close_session_command (struct she_platform_hdl *phdl, uint32_t session_handle);
she_err_t she_get_shared_buffer(struct she_platform_hdl *phdl, uint32_t session_handle, uint32_t *shared_buf_offset, uint32_t *shared_buf_size);
she_err_t she_open_session_command (struct she_platform_hdl *phdl, uint32_t *session_handle, uint8_t mu_id, uint8_t interrupt_idx, uint8_t tz, uint8_t did, uint8_t priority,uint8_t operating_mode);

#endif
