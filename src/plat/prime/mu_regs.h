/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#ifndef MU_REGS_H
#define MU_REGS_H

#include <stdint.h>

#define REQ_SUCCESS	0xd6
#define PRIME_FIFO_FULL	0x2029
#define PRIME_MAX_MSG	40U

struct mu_type {
	uint32_t ver;
	uint32_t par;
	uint32_t cr;
	uint32_t sr;
	uint32_t reserved0[60];
	uint32_t fcr;
	uint32_t fsr;
	uint32_t reserved1[2];
	uint32_t gier;
	uint32_t gcr;
	uint32_t gsr;
	uint32_t reserved2;
	uint32_t tcr;
	uint32_t tsr;
	uint32_t rcr;
	uint32_t rsr;
	uint32_t reserved3[52];
	uint32_t tr[16];
	uint32_t reserved4[16];
	uint32_t rr[16];
	uint32_t reserved5[14];
	uint32_t mu_attr;
};

struct prime_msg {
	volatile uint8_t version;
	volatile uint8_t size;
	volatile uint8_t command;
	volatile uint8_t tag;
	uint32_t data[(PRIME_MAX_MSG - 1U)];
};

struct prime_load_key_msg {
	volatile uint8_t version;
	volatile uint8_t size;
	volatile uint8_t command;
	volatile uint8_t tag;
	volatile uint8_t keyslot;
	volatile uint8_t keysize;
	uint8_t rfu[2];
	uint32_t data[(PRIME_MAX_MSG - 2U)];
};

int imx_mu_send_recv(void *base, void *tx_msg, void *rx_msg);
void imx_mu_init(struct mu_type *base);

#endif /* MU_REGS_H */
