// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

/**
 * @file hash.c
 * @brief PRIME FCE Hash Generate API
 *
 * Uses FCE HASH Generate command (0x80) via CRYPTO_OP_TYPE_HASH dispatch.
 *
 * FCE HASH Generate message layout:
 *   W0: Header  (cmd=0x80, size=0x18)
 *   W1: Status Address
 *   W2: Flags   (bits[5:4]=hash_algo, bit1=AutoPOP, bit0=Signal)
 *   W3: Digest Address
 *   W4: Payload Byte Length
 *   W5: Input Address
 *
 * Supported algorithms (FCE flags bits[5:4]):
 *   CRYPTO_HASH_SHA2_256 (1) -> SHA256, 32-byte digest
 *   CRYPTO_HASH_SHA2_384 (2) -> SHA384, 48-byte digest
 *   CRYPTO_HASH_SHA2_512 (3) -> SHA512, 64-byte digest
 */

#include <stdio.h>
#include <stdint.h>
#include "sab_prime_mac.h"
#include "sab_prime_process_msg.h"

static const uint32_t hash_digest_sz[] = {
	[CRYPTO_HASH_SHA2_256] = PRIME_HASH_DIGEST_SZ_SHA256,
	[CRYPTO_HASH_SHA2_384] = PRIME_HASH_DIGEST_SZ_SHA384,
	[CRYPTO_HASH_SHA2_512] = PRIME_HASH_DIGEST_SZ_SHA512,
};

/**
 * prime_hash_one_go - compute a hash digest in a single FCE operation
 *
 * @service_hdl: handle to an open PRIME service session
 * @args:        pointer to hash one go arguments
 *
 * Return: PRIME_ERR_NONE on success, PRIME_ERR_INVALID_PARAM on bad args,
 *         PRIME_ERROR on failure.
 */
prime_err_t prime_hash_one_go(prime_hdl_t service_hdl,
			      hash_one_go_args_t *args)
{
	crypto_op_args_t op = {0};
	crypto_op_args_t *op_ptr = &op;
	int err;

	if (!args || !args->input || !args->output ||
	    !args->input_size || !args->output_size ||
	    !args->input_phys || !args->output_phys) {
		printf("%s: invalid arguments\n", __func__);
		return PRIME_ERR_INVALID_PARAM;
	}

	if (args->algo < CRYPTO_HASH_SHA2_256 || args->algo > CRYPTO_HASH_SHA2_512) {
		printf("%s: invalid algo %u\n", __func__, args->algo);
		return PRIME_ERR_INVALID_PARAM;
	}

	if (args->output_size != hash_digest_sz[args->algo]) {
		printf("%s: output_size %u does not match algo %u digest size %u\n",
		       __func__, args->output_size, args->algo,
			hash_digest_sz[args->algo]);
		return PRIME_ERR_INVALID_PARAM;
	}
	/* Source buffer */
	op.src.virt_addr = (uint8_t *)args->input;
	op.src.phys_addr = args->input_phys;
	op.src.len       = args->input_size;

	/* CRYPTO_OP_TYPE_HASH skips keyslot validation in prime_process_ops() */
	op.op_type = CRYPTO_OP_TYPE_HASH;

	/* algo value (1/2/3) maps directly to FCE flags bits[5:4] */
	op.op_hash_args.algo             = args->algo;
	op.op_hash_args.flags            = 0;
	op.op_hash_args.digest.virt_addr = args->output;
	op.op_hash_args.digest.phys_addr = args->output_phys;
	op.op_hash_args.digest.len       = args->output_size;

	/*
	 * Status buffer: placed at ALIGN_UP(output_size, 64) beyond the digest.
	 * Caller must allocate output buffer with this extra space.
	 */
	op.crypto_status.phys_addr =
		(status_buf_t *)(args->output_phys +
				 ((args->output_size + 63u) & ~63u));
	op.crypto_status.virt_addr =
		(status_buf_t *)(args->output +
				 ((args->output_size + 63u) & ~63u));

	err = prime_process_ops(service_hdl, &op_ptr, 1);
	if (err) {
		printf("%s: prime_process_ops failed (%d)\n", __func__, err);
		return PRIME_ERROR;
	}

	return PRIME_ERR_NONE;
}
