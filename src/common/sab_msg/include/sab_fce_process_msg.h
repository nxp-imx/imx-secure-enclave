// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef SAB_FCE_PROCESS_MSG_H
#define SAB_FCE_PROCESS_MSG_H

#include "prime.h"

#define FCE_MAX_OPS	32
#define FCE_REQ_ID_DIFF	0x10
#define FCE_SIG_POP_REQ	0x3
#define FCE_POP_REQ	0x2

#define REQ_VERIFY_FAIL	0x6029

struct uio_fce_mu *get_uio_fce_mu(void);

void v2x_prime_init(void);
void v2x_prime_deinit(void);
void prime_process_ops(uint32_t service_hdl, crypto_op_args_t **ops,
		       uint32_t nb_ops);

#endif
