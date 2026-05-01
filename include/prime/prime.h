// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
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
	CRYPTO_OP_COMPLETED, // dequeue done, after getting interrupt
	CRYPTO_OP_SUBMITTED, // enqueue done
	CRYPTO_OP_FIFO_FULL, // push fail
};

/* Status buffer structure updated by firmware */
typedef struct status_buf {
	uint8_t status_code;	/* 0xD6 = success, other = error */
	uint8_t error_info;	/* Additional error information */
	uint16_t reserved;	/* Reserved for future use */
} status_buf_t;

struct crypto_status {
	status_buf_t *phys_addr;
	status_buf_t *virt_addr;
};

/* PRIME crypto private session structure */
typedef struct prime_crypto_op {
	struct buf src;
	struct buf dst;
	uint32_t req_id; // to be deleted from user interface
	struct crypto_status crypto_status;
	enum crypto_op_status op_status;
	enum crypto_op_type op_type;

	union {
		struct aes_op_params op_aes_args;
		struct aead_op_params op_aead_args;
		struct mac_op_params op_mac_args;
	};
} crypto_op_args_t;

int prime_process_ops(prime_hdl_t service_hdl,
		      crypto_op_args_t **ops,
		      uint32_t nb_ops);

#endif
