// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
 */

#include "sab_common_err.h"
#include "sab_messaging.h"
#include "sab_msg_def.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

void set_phy_addr_to_words(uint32_t *lsb, uint32_t *msb, uint64_t phy_addr)
{
	if (lsb)
		*lsb = (uint32_t)(phy_addr & 0xFFFFFFFF);

	if (msb)
		*msb = (uint32_t)((phy_addr >> 32) & 0xFFFFFFFF);
}

uint32_t sab_get_shared_buffer(struct plat_os_abs_hdl *phdl, uint32_t session_handle, uint32_t mu_type)
{
    struct sab_cmd_shared_buffer_msg cmd;
    struct sab_cmd_shared_buffer_rsp rsp;
	int32_t error;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        /* Send the keys store open command to Platform. */
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_SHARED_BUF_REQ, (uint32_t)sizeof(struct sab_cmd_shared_buffer_msg), mu_type);

        cmd.session_handle = session_handle;
        error = plat_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_shared_buffer_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_shared_buffer_rsp));
        if (error != 0) {
            break;
        }

		sab_err_map(SAB_SHARED_BUF_REQ, rsp.rsp_code);

        ret = rsp.rsp_code;
        if (GET_STATUS_CODE(ret) != SAB_SUCCESS_STATUS) {
            break;
        }

        /* Configure the shared buffer. */
        error = plat_os_abs_configure_shared_buf(phdl, rsp.shared_buf_offset, rsp.shared_buf_size);
        if (error != 0) {
            ret = SAB_FAILURE_STATUS;
            break;
        }
        ret = SAB_SUCCESS_STATUS;
    } while(false);
    return ret;
}

uint32_t sab_open_sm2_eces(struct plat_os_abs_hdl *phdl, uint32_t key_store_handle, uint32_t *sm2_eces_handle, uint32_t mu_type, uint8_t flags)
{
    struct sab_cmd_sm2_eces_dec_open_msg cmd;
    struct sab_cmd_sm2_eces_dec_open_rsp rsp;
	int32_t error;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_SM2_ECES_DEC_OPEN_REQ, (uint32_t)sizeof(struct sab_cmd_sm2_eces_dec_open_msg), mu_type);
        cmd.input_address_ext = 0;
        cmd.output_address_ext = 0;
        cmd.flags = flags;
        cmd.key_store_handle = key_store_handle;
        cmd.rsv[0] = 0u;
		cmd.rsv[1] = 0u;
		cmd.rsv[2] = 0u;
        cmd.crc = 0u;
        cmd.crc = plat_compute_msg_crc((uint32_t*)&cmd, (uint32_t)(sizeof(cmd) - sizeof(uint32_t)));

        error = plat_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_sm2_eces_dec_open_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_sm2_eces_dec_open_rsp));
        if (error != 0) {
            break;
        }

		sab_err_map(SAB_SM2_ECES_DEC_OPEN_REQ, rsp.rsp_code);

        ret = rsp.rsp_code;
        *sm2_eces_handle = rsp.sm2_eces_handle;
    } while(false);
    return ret;
}

uint32_t sab_close_sm2_eces(struct plat_os_abs_hdl *phdl, uint32_t sm2_eces_handle, uint32_t mu_type)
{
    struct sab_cmd_sm2_eces_dec_close_msg cmd;
    struct sab_cmd_sm2_eces_dec_close_rsp rsp;
	int32_t error;
    uint32_t ret = SAB_FAILURE_STATUS;

    do {
        plat_fill_cmd_msg_hdr(&cmd.hdr, SAB_SM2_ECES_DEC_CLOSE_REQ, (uint32_t)sizeof(struct sab_cmd_sm2_eces_dec_close_msg), mu_type);
        cmd.sm2_eces_handle = sm2_eces_handle;
        error = plat_send_msg_and_get_resp(phdl,
                    (uint32_t *)&cmd, (uint32_t)sizeof(struct sab_cmd_sm2_eces_dec_close_msg),
                    (uint32_t *)&rsp, (uint32_t)sizeof(struct sab_cmd_sm2_eces_dec_close_rsp));

        if (error != 0) {
            break;
        }

		sab_err_map(SAB_SM2_ECES_DEC_CLOSE_REQ, rsp.rsp_code);

        ret = rsp.rsp_code;
    } while(false);
    return ret;
}
