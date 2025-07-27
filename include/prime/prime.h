// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef PRIME_H
#define PRIME_H

#include <stddef.h>

#include "internal/prime_handle.h"
#include "internal/prime_hmac.h"
#include "internal/prime_aes.h"
#include "internal/prime_service.h"

enum crypto_op_type {
	CRYPTO_OP_TYPE_NONE,
	CRYPTO_OP_TYPE_AES,
	CRYPTO_OP_TYPE_AEAD,
	CRYPTO_OP_TYPE_HMAC,
	CRYPTO_OP_TYPE_MAX,
};

/* Status of crypto operation */
enum crypto_op_status {
	CRYPTO_OP_SUCCESS,
	CRYPTO_OP_IN_PROGRESS,
	CRYPTO_OP_AUTH_FAILED,
	CRYPTO_OP_INVALID_ARGS,
	CRYPTO_OP_FIFO_FULL,
	CRYPTO_OP_ERROR,
};

/* PRIME crypto private session structure */
typedef struct crypto_op {
	struct buf src;
	struct buf dst;
	uint32_t req_id;
	enum crypto_op_status status;
	enum crypto_op_type op_type;

	union {
		struct aes_op_params op_aes_args;
		struct aead_op_params op_aead_args;
		struct auth_op_params op_auth_args;
	};
} crypto_op_args_t;

void prime_process_ops(prime_hdl_t service_hdl,
		       crypto_op_args_t **ops,
		       uint32_t nb_ops);

#endif
