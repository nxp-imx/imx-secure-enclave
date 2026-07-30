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
#include "utils.h"

static int dequeue_ops(crypto_op_args_t **ops, uint32_t nb_ops)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();
	uint32_t req_id, last_req_id;
	int status, err = 0, i;

	err = prime_deq(prime_mu->fd);

	if (!err) {
		for (i = 0; i < nb_ops; i++)
			ops[i]->op_status = CRYPTO_OP_COMPLETED;
	} else {
		printf("[dequeue_ops] ERROR: Dequeue failed with error %d\n", err);
	}

	return err;
}

static uint32_t build_op(prime_hdl_t handle, crypto_op_args_t *op,
			 uint8_t buf_off, uint8_t flag)
{
	uint32_t ret;
	prime_service_t *hdl;

	hdl = prime_session_to_ptr(handle);
	if (!hdl) {
		printf("Invalid handle\n");
		return CRYPTO_OP_INVALID_HANDLE;
	}

	switch (op->op_type) {
	case CRYPTO_OP_TYPE_AES:
		ret = prime_cipher_build(hdl, op, buf_off, flag);
		break;
	case CRYPTO_OP_TYPE_AEAD:
		ret = prime_aead_build(hdl, op, buf_off, flag);
		break;
	case CRYPTO_OP_TYPE_HMAC:
		ret = prime_mac_build(hdl, op, buf_off, flag);
		break;
	case CRYPTO_OP_TYPE_HASH:
		ret = prime_hash_build(hdl, op, buf_off, flag);
		break;
	default:
		printf("Un-supported crypto operation.\n");
		ret = CRYPTO_OP_INVALID_ALGO;
		break;
	};

	return ret;
}

static int enqueue_ops(prime_hdl_t handle, crypto_op_args_t **ops,
		       uint16_t nb_ops, uint8_t flag)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();
	uint8_t slot = 0, jobs = 0, buf_off = 64;
	int i;
	int ret;
	uint32_t req_id;

	/* Push Request: MU Slot */
	for (i = 0; i < nb_ops; i++) {
		if (flag && (i + 1 == nb_ops))
			ret = build_op(handle, ops[i], buf_off * i, PRIME_SIG_POP_REQ);
		else
			ret = build_op(handle, ops[i], buf_off * i, PRIME_POP_REQ);
		if (ret) {
			ops[i]->op_status = ret;
			return 0;
		}

		slot = slot | (1 << i);
		jobs++;
	}

	if (slot) {
		/*
		 * Update producer_req_id_index before push to consider the case
		 * of receiving job success interrupt before push command response.
		 * This is speculative and is re-anchored to the authoritative
		 * req_id below on the success path (and rolled back on error).
		 */
		producer_req_id_index += (nb_ops * PRIME_REQ_ID_DIFF);

		req_id = prime_push(prime_mu->base, slot);
		/*
		 * if last nibble is set, it means there is error in push command
		 * because req_id is always incremented by 0x10
		 */
		if (req_id & NIBBLE_MASK) {
			for (i = 0; i < nb_ops; i++)
				ops[i]->op_status = CRYPTO_OP_FIFO_FULL;

			producer_req_id_index -= (nb_ops * PRIME_REQ_ID_DIFF);

			/* It returns num of jobs completed, returning 0 means error */
			return 0;
		}

		/*
		 * Re-anchor producer_req_id_index to the authoritative req_id
		 * returned by firmware for the last op in this batch. The value
		 * seeded at init from the FW request-id register is ambiguous
		 * for the value 0 (it cannot tell a fresh boot from the state
		 * where exactly one op has already completed), which otherwise
		 * desyncs producer vs consumer on the second op after reboot.
		 *
		 * req_id already reflects the cumulative state after all nb_ops
		 * slots in this batch (req_id == base + nb_ops * PRIME_REQ_ID_DIFF),
		 * so this assignment subsumes the speculative increment above.
		 */
		producer_req_id_index = req_id;
	}

	/* save the request id for each op and set the status */
	/* req_id is incremented by firmware by 0x10 after every request */
	for (i = nb_ops - 1; i >= 0; i--) {
		if (slot & (1 << i)) {
			ops[i]->req_id = req_id;
			req_id = req_id - PRIME_REQ_ID_DIFF;
			ops[i]->op_status = CRYPTO_OP_SUBMITTED;
		}
	}

	return jobs;
}

static int run_ops(prime_hdl_t handle, crypto_op_args_t **ops, uint32_t nb_ops)
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

		enqd_ops = enqueue_ops(handle, &ops[i], cnt_ops, flag);

		if (!enqd_ops)
			break;

		i += cnt_ops;
	}

	/* read the status and clear the error jobs in fw queue */
	if (i)
		ret = dequeue_ops(ops, i);

	return ret;
}

int prime_process_ops(prime_hdl_t service_hdl,
		      crypto_op_args_t **ops,
		      uint32_t nb_ops)
{
	uint32_t max_ops = PRIME_MAX_OPS;
	uint32_t unused_ops = nb_ops;
	uint32_t enq_ops;
	int ret;
	prime_service_t *hdl;

	hdl = prime_session_to_ptr(service_hdl);
	if (!hdl) {
		printf("Invalid handle\n");
		return -1;
	}

	for (uint32_t i = 0; i < nb_ops; i = i + enq_ops) {
		enq_ops = (unused_ops > max_ops) ? max_ops : unused_ops;
		/* Check if address is in range of owned address */
		if (ops[i]->src.phys_addr < hdl->physical_addr ||
		    (ops[i]->src.phys_addr + ops[i]->src.len) >
		    (hdl->physical_addr + hdl->size)) {
			printf("Not correct owner for ops %d\n", i);
			return -1;
		}

		/* Check for valid keyslot */
		switch (ops[i]->op_type) {
		case CRYPTO_OP_TYPE_AES:
			if (!(hdl->aes_keyslot_map &
			    BIT(ops[i]->op_aes_args.keyslot))) {
				printf("Invalid Keyslot for ops %d\n", i);
				return -1;
			}
			break;
		case CRYPTO_OP_TYPE_AEAD:
			if (!(hdl->aes_keyslot_map &
			    BIT(ops[i]->op_aead_args.keyslot))) {
				printf("Invalid Keyslot for ops %d\n", i);
				return -1;
			}
			break;
		case CRYPTO_OP_TYPE_HMAC:
			if (!(hdl->hmac_keyslot_map &
			    BIT(ops[i]->op_mac_args.keyslot))) {
				printf("Invalid Keyslot for ops %d\n", i);
				return -1;
			}
			break;
		case CRYPTO_OP_TYPE_HASH:
			/* Hash one go does not use a key slot */
			break;
		}

		ret = run_ops(service_hdl, &ops[i], enq_ops);
		if (ret)
			break;

		unused_ops = unused_ops - enq_ops;
	}

	if (unused_ops)
		printf("V2X Prime: %u ops not processed\n", unused_ops);

	return ret;
}
