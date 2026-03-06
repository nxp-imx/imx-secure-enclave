// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include <stdint.h>

#include "prime.h"

#include "sab_prime_process_msg.h"
#include "sab_prime_api.h"
#include "sab_prime_pvt.h"
#include "uio.h"

static void set_status(crypto_op_args_t **ops, uint16_t nb_ops, int req_id,
		       int status)
{
	int i;

	for (i = 0; i < nb_ops; i++) {
		if (ops[i]->req_id == req_id) {
			if (status == REQ_VERIFY_FAIL)
				ops[i]->status = CRYPTO_OP_AUTH_FAILED;
			else
				ops[i]->status = CRYPTO_OP_ERROR;

			break;
		}
	}
}

static int dequeue_ops(crypto_op_args_t **ops, uint32_t nb_ops)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();
	uint32_t req_id, last_req_id;
	int status, err = 0;

	err = prime_deq(prime_mu->fd);
	if (!err)
		return err;

	/* Error signal is set, clear the FW qeuue by reading error job */
	last_req_id = ops[nb_ops - 1]->req_id;
	do {
		req_id = last_req_id;
		status = prime_get_request_status(prime_mu->base, &req_id);
		if (status != 0xd6)
			set_status(ops, nb_ops, req_id, status);

	} while (req_id < last_req_id);

	return err;
}

static void build_op(crypto_op_args_t *op, uint8_t buf_off, uint8_t flag)
{
	switch (op->op_type) {
	case CRYPTO_OP_TYPE_AES:
		prime_cipher_build(op, buf_off, flag);
		break;
	case CRYPTO_OP_TYPE_AEAD:
		prime_aead_build(op, buf_off, flag);
		break;
	case CRYPTO_OP_TYPE_HMAC:
		prime_auth_build(op, buf_off, flag);
		break;
	default:
		printf("Un-supported crypto operation.\n");
		break;
	};

	return;
}

static int enqueue_ops(crypto_op_args_t **ops, uint16_t nb_ops, uint8_t flag)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();
	uint8_t slot = 0, jobs = 0, buf_off = 64;
	int i, ret, req_id;

	/* Push Request: MU Slot */
	for (i = 0; i < nb_ops; i++) {
		if (flag && (i + 1 == nb_ops))
			build_op(ops[i], buf_off * i, PRIME_SIG_POP_REQ);
		else
			build_op(ops[i], buf_off * i, PRIME_POP_REQ);

		slot = slot | (1 << i);
		jobs++;
	}

	if (slot) {
		req_id = prime_push(prime_mu->base, slot);
		if (req_id < 0) {
			for (i = 0; i < nb_ops; i++)
				ops[i]->status = CRYPTO_OP_FIFO_FULL;

			return 0;
		}
	}

	/* save the request id for each op and set the status */
	for (i = nb_ops - 1; i >= 0; i--) {
		if (slot & (1 << i)) {
			ops[i]->req_id = req_id;
			req_id = req_id - PRIME_REQ_ID_DIFF;
			ops[i]->status = CRYPTO_OP_IN_PROGRESS;
		}
	}

	return jobs;
}

static int run_ops(crypto_op_args_t **ops, uint32_t nb_ops)
{
	uint32_t cnt_ops, enqd_ops, i;
	uint8_t flag;
	int ret = 0;

	i = 0;
	while (i < nb_ops) {
		if ((nb_ops - i) > 4) {
			cnt_ops = 4;
			flag = 0;
		} else {
			cnt_ops = nb_ops - i;
			flag = 1;
		}

		enqd_ops = enqueue_ops(&ops[i], cnt_ops, flag);
		if (enqd_ops < cnt_ops)
			break;

		i += cnt_ops;
	}

	/* read the status and clear the error jobs in fw queue */
	ret = dequeue_ops(ops, i);

	if (i != nb_ops)
		return CRYPTO_OP_ENQ_ERR;

	return ret;
}

int prime_process_ops(uint32_t service_hdl,
		      crypto_op_args_t **ops,
		      uint32_t nb_ops)
{
	uint32_t max_ops = PRIME_MAX_OPS;
	uint32_t unused_ops = nb_ops;
	uint32_t enq_ops;
	int ret = CRYPTO_OP_SUCCESS;

	for (uint32_t i = 0; i < nb_ops; i = i + enq_ops) {
		enq_ops = (unused_ops > max_ops) ? max_ops : unused_ops;
		ret = run_ops(&ops[i], enq_ops);
		if (ret)
			break;

		unused_ops = unused_ops - enq_ops;
	}

	if (unused_ops)
		printf("V2X Prime: %u ops not processed\n", unused_ops);

	return ret;
}
