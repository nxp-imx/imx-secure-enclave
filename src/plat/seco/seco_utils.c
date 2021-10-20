/*
 * Copyright 2019-2021 NXP
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

#include "seco_os_abs.h"
#include "seco_utils.h"

/* Fill a command message header with a given command ID and length in bytes. */
void seco_fill_cmd_msg_hdr(struct sab_mu_hdr *hdr, uint8_t cmd, uint32_t len, uint32_t mu_type)
{
    switch (mu_type) {
    case MU_CHANNEL_V2X_SV0:
        hdr->tag = V2X_SV0_REQ_TAG;
        hdr->ver = V2X_SV0_API_VER;
        break;
    case MU_CHANNEL_V2X_SV1:
        hdr->tag = V2X_SV1_REQ_TAG;
        hdr->ver = V2X_SV1_API_VER;
        break;
    case MU_CHANNEL_V2X_SHE:
    case MU_CHANNEL_V2X_SHE_NVM:
        hdr->tag = V2X_SHE_REQ_TAG;
        hdr->ver = V2X_SHE_API_VER;
        break;
    case MU_CHANNEL_V2X_SG0:
        hdr->tag = V2X_SG0_REQ_TAG;
        hdr->ver = V2X_SG0_API_VER;
        break;
    case MU_CHANNEL_V2X_SG1:
    case MU_CHANNEL_V2X_HSM_NVM:
        hdr->tag = V2X_SG1_REQ_TAG;
        hdr->ver = V2X_SG1_API_VER;
        break;
    default:
        hdr->tag = MESSAGING_TAG_COMMAND;
        hdr->ver = MESSAGING_VERSION_6;
        break;
    }
    hdr->command = cmd;
    hdr->size = (uint8_t)(len / sizeof(uint32_t));
};

/* Fill a response message header with a given command ID and length in bytes. */
void seco_fill_rsp_msg_hdr(struct sab_mu_hdr *hdr, uint8_t cmd, uint32_t len, uint32_t mu_type)
{
    switch (mu_type) {
    case MU_CHANNEL_V2X_SV0:
        hdr->tag = V2X_SV0_IND_TAG;
        hdr->ver = V2X_SV0_API_VER;
        break;
    case MU_CHANNEL_V2X_SV1:
        hdr->tag = V2X_SV1_IND_TAG;
        hdr->ver = V2X_SV1_API_VER;
        break;
    case MU_CHANNEL_V2X_SHE:
    case MU_CHANNEL_V2X_SHE_NVM:
        hdr->tag = V2X_SHE_IND_TAG;
        hdr->ver = V2X_SHE_API_VER;
        break;
    case MU_CHANNEL_V2X_SG0:
        hdr->tag = V2X_SG0_IND_TAG;
        hdr->ver = V2X_SG0_API_VER;
        break;
    case MU_CHANNEL_V2X_SG1:
    case MU_CHANNEL_V2X_HSM_NVM:
        hdr->tag = V2X_SG1_IND_TAG;
        hdr->ver = V2X_SG1_API_VER;
        break;
    default:
        hdr->tag = MESSAGING_TAG_RESPONSE;
        hdr->ver = MESSAGING_VERSION_6;
        break;
    }
    hdr->command = cmd;
    hdr->size = (uint8_t)(len / sizeof(uint32_t));
};

/* Helper function to send a message and wait for the response. Return 0 on success.*/
int32_t seco_send_msg_and_get_resp(struct seco_os_abs_hdl *phdl, uint32_t *cmd, uint32_t cmd_len, uint32_t *rsp, uint32_t rsp_len)
{
    int32_t err = -1;
    int32_t len;

    do {
        /* Command and response need to be at least 1 word for the header. */
        if ((cmd_len < (uint32_t)sizeof(uint32_t)) || (rsp_len < (uint32_t)sizeof(uint32_t))) {
            break;
        }

        /* Send the command. */
        len = seco_os_abs_send_mu_message(phdl, cmd, cmd_len);
        if (len != (int32_t)cmd_len) {
            break;
        }
        /* Read the response. */
        len = seco_os_abs_read_mu_message(phdl, rsp, rsp_len);

        err = 0;
    } while (false);
    return err;
}

uint32_t seco_compute_msg_crc(uint32_t *msg, uint32_t msg_len)
{
    uint32_t crc;
    uint32_t i;
    uint32_t nb_words = msg_len / (uint32_t)sizeof(uint32_t);

    crc = 0u;
    for (i = 0u; i < nb_words; i++) {
        crc ^= *(msg + i);
    }
    return crc;
}
