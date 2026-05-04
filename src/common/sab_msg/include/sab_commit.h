// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef SAB_COMMIT_H
#define SAB_COMMIT_H

#include "sab_msg_def.h"

/**
 * struct rom_cmd_commit_msg - COMMIT command message (0xA8)
 * @hdr: Message header
 * @info_type: Bitmask of information types to commit
 *
 * Command format:
 * Word 0: Tag (0x17), Command ID (0xA8), Word size (0x2), Version (0x06)
 * Word 1: Information type to be committed
 */
struct rom_cmd_commit_msg {
	struct sab_mu_hdr hdr;
	uint32_t info_type;
};

/**
 * struct rom_cmd_commit_rsp - COMMIT response message
 * @hdr: Response header
 * @rsp_code: Response indicator
 * @committed_info: Bitmask of information actually committed
 *
 * Response format:
 * Word 0: Tag (0xE1), Command ID (0xA8), Word size (0x3), Version (0x06)
 * Word 1: Response indicator
 * Word 2: Information type that has been committed
 */
struct rom_cmd_commit_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t committed_info;
};

uint32_t prepare_msg_commit(void *phdl, void *cmd_buf, void *rsp_buf,
			    uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
			    uint32_t msg_hdl, void *args);

uint32_t proc_msg_rsp_commit(void *rsp_buf, void *args);

#endif
