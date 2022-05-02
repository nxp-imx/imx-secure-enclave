/*
 * Copyright 2021-2022 NXP
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

#include "plat_os_abs.h"
#include "plat_utils.h"

/* Soon to be depricated to help descriminate between ROM and Firmware API */
void plat_fill_cmd_msg_hdr(struct sab_mu_hdr *hdr, uint8_t cmd, uint32_t len, uint32_t mu_type)
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
        hdr->ver = MESSAGING_VERSION_7;
        break;
    }
    hdr->command = cmd;
    hdr->size = (uint8_t)(len / sizeof(uint32_t));
};

/* Fill a command message header with a given command ID and length in bytes. */
void plat_build_cmd_msg_hdr(struct sab_mu_hdr *hdr, msg_type_t msg_type,
			uint8_t cmd, uint32_t len, uint32_t mu_type)
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
		hdr->ver = MESSAGING_VERSION_7;
		if (msg_type == ROM_MSG)
			hdr->ver = MESSAGING_VERSION_6;
		break;
	}
	hdr->command = cmd;
	hdr->size = (uint8_t)(len / sizeof(uint32_t));
};

/* Fill a response message header with a given command ID and length in bytes. */
void plat_fill_rsp_msg_hdr(struct sab_mu_hdr *hdr, uint8_t cmd, uint32_t len, uint32_t mu_type)
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
        hdr->ver = MESSAGING_VERSION_7;
        break;
    }
    hdr->command = cmd;
    hdr->size = (uint8_t)(len / sizeof(uint32_t));
};

static void hexdump(uint32_t buf[], uint32_t size)
{
	int i = 0;

	for (; i < size; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%08x ", buf[i]);
	}
}

/* Helper function to send a message and wait for the response. Return 0 on success.*/
int32_t plat_send_msg_and_get_resp(struct plat_os_abs_hdl *phdl, uint32_t *cmd, uint32_t cmd_len, uint32_t *rsp, uint32_t rsp_len)
{
    int32_t err = -1;
    int32_t len;

    do {
        /* Command and response need to be at least 1 word for the header. */
        if ((cmd_len < (uint32_t)sizeof(uint32_t)) || (rsp_len < (uint32_t)sizeof(uint32_t))) {
            break;
        }

        /* Send the command. */
        len = plat_os_abs_send_mu_message(phdl, cmd, cmd_len);
        if (len != (int32_t)cmd_len) {
            break;
        }
#if DEBUG
	printf("\n---------- MSG Command with msg id[0x%x] = %d -------------\n",
			((struct sab_mu_hdr *)cmd)->command,
			((struct sab_mu_hdr *)cmd)->command);
	hexdump(cmd, cmd_len);
	printf("\n-------------------MSG END-----------------------------------\n");
#endif
        /* Read the response. */
        len = plat_os_abs_read_mu_message(phdl, rsp, rsp_len);
#if DEBUG
	printf("\n---------- MSG Command RSP with msg id[0x%x] = %d -------------\n",
			((struct sab_mu_hdr *)rsp)->command,
			((struct sab_mu_hdr *)rsp)->command);
	hexdump(rsp, rsp_len);
	printf("\n-------------------MSG RSP END-----------------------------------\n");
#endif

        err = 0;
    } while (false);

    return err;
}

uint32_t plat_compute_msg_crc(uint32_t *msg, uint32_t msg_len)
{
	uint32_t crc;
	uint32_t i;
	uint32_t nb_words = msg_len / (uint32_t)sizeof(uint32_t);

	crc = 0u;
	for (i = 0u; i < nb_words; i++) {
		crc ^= *(msg + i);
	}
	msg[nb_words] = crc;
	return crc;
}

uint32_t get_lib_version(void)
{
	return LIB_MAJOR_VERSION << 8 + LIB_MINOR_VERSION;
}
