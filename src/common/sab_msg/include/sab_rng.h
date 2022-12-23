/*
 * Copyright 2019-2022 NXP
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

#ifndef SAB_RNG_H
#define SAB_RNG_H

#include "sab_msg_def.h"

struct sab_cmd_get_rnd_msg {
	struct sab_mu_hdr hdr;
#ifdef PSA_COMPLIANT
	uint32_t rnd_addr_msb;
#else
	uint32_t rng_handle;
#endif
	uint32_t rnd_addr;
	uint32_t rnd_size;
};

struct sab_cmd_get_rnd_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_get_rng(void *phdl,
			     void *cmd_buf, void *rsp_buf,
			     uint32_t *cmd_msg_sz,
			     uint32_t *rsp_msg_sz,
			     uint32_t msg_hdl,
			     void *args);

uint32_t proc_msg_rsp_get_rng(void *rsp_buf, void *args);

#ifndef PSA_COMPLIANT
struct sab_cmd_rng_open_msg {
	struct sab_mu_hdr hdr;
	uint32_t session_handle;
	uint32_t input_address_ext;
	uint32_t output_address_ext;
	uint8_t flags;
	uint8_t pad[3];
	uint32_t crc;
};

struct sab_cmd_rng_open_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t rng_handle;
};

struct sab_cmd_rng_close_msg {
	struct sab_mu_hdr hdr;
	uint32_t rng_handle;
};

struct sab_cmd_rng_close_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

uint32_t prepare_msg_rng_open_req(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args);

uint32_t proc_msg_rsp_rng_open_req(void *rsp_buf, void *args);

uint32_t prepare_msg_rng_close_req(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args);

uint32_t proc_msg_rsp_rng_close_req(void *rsp_buf, void *args);
#endif
#endif // SAB_RNG_H
