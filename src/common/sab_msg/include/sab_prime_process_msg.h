// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef SAB_PRIME_PROCESS_MSG_H
#define SAB_PRIME_PROCESS_MSG_H

#include "prime.h"
#include "uio.h"

#define PRIME_MAX_OPS		32
#define PRIME_SIG_POP_REQ	0x3
#define PRIME_POP_REQ		0x2

#define REQ_VERIFY_FAIL		0x6029

#define PRIME_REQ_ID_OFFSET		0xFC
#define PRIME_REQ_ID_DIFF		0x10
/*
 * 0 is a valid request ID so decrementing the producer index
 * by PRIME_REQ_ID_DIFF if initial value is 0
 */
#define PRIME_PRODUCE_INDEX_INIT_VAL	(0 - PRIME_REQ_ID_DIFF)
#define NIBBLE_MASK			0xF

/* Global variables for tracking request IDs */
extern uint32_t producer_req_id_index;
extern uint32_t consumer_req_id_index;

struct uio_prime_mu *get_uio_prime_mu(void);

void v2x_prime_init(void);
void v2x_prime_deinit(void);
int prime_process_ops(prime_hdl_t service_hdl,
		      crypto_op_args_t **ops,
		      uint32_t nb_ops);

#endif
