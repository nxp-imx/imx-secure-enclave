/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>

#include "prime.h"
#include "sab_prime_process_msg.h"
#include "sab_prime_auth.h"
#include "sab_prime_aes.h"
#include "uio.h"

int prime_auth_build(crypto_op_args_t *op,
		     uint8_t buf_off,
		     uint8_t flag)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();
	uint32_t *mu_buf = (uint32_t *)(prime_mu->mu_buf + buf_off);

	prime_auth_construct(mu_buf, op->op_auth_args.keyslot,
			     op->src.phys_addr, op->src.len,
			     op->op_auth_args.digest.phys_addr, op->op_auth_args.sha_algo,
			     op->op_auth_args.dir, flag);

	return 0;
}

int prime_cipher_build(crypto_op_args_t *op,
		       uint8_t buf_off,
		       uint8_t flag)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();
	uint32_t *mu_buf = (uint32_t *)(prime_mu->mu_buf + buf_off);
	uint32_t digest_addr = 0;
	uint8_t sha_algo = 0;

	switch (op->op_aes_args.algo) {
	case CRYPTO_CIPHER_AES_CBC:
		prime_cbc_construct(mu_buf, op->op_aes_args.keyslot,
				    op->src.phys_addr, op->dst.phys_addr,
				    op->src.len, op->op_aes_args.enc,
				    op->op_aes_args.iv, op->op_aes_args.ivlen,
				    digest_addr, sha_algo, flag);
		break;
	case CRYPTO_CIPHER_AES_ECB:
		prime_ecb_construct(mu_buf, op->op_aes_args.keyslot,
				    op->src.phys_addr, op->dst.phys_addr,
				    op->src.len, op->op_aes_args.enc,
				    digest_addr, sha_algo, flag);
		break;
	case CRYPTO_CIPHER_AES_CTR:
		prime_ctr_construct(mu_buf, op->op_aes_args.keyslot,
				    op->src.phys_addr, op->dst.phys_addr,
				    op->src.len, op->op_aes_args.enc,
				    op->op_aes_args.iv, op->op_aes_args.ivlen,
				    digest_addr, sha_algo, flag);
		break;
	default:
		printf("unsupported cipher algo %u", op->op_aes_args.algo);
		return -1;
	}

	return 0;
}

int prime_aead_build(crypto_op_args_t *op,
		     uint8_t buf_off,
		     uint8_t flag)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();
	uint32_t *mu_buf = (uint32_t *)(prime_mu->mu_buf + buf_off);

	switch (op->op_aead_args.algo) {
	case CRYPTO_AEAD_AES_GCM:
		prime_gcm_construct(mu_buf, op->op_aead_args.keyslot,
				    op->src.phys_addr, op->dst.phys_addr,
				    op->src.len, op->op_aead_args.enc,
				    op->op_aead_args.iv, op->op_aead_args.ivlen,
				    op->op_aead_args.aad.phys_addr,
				    op->op_aead_args.aad.len,
				    op->op_aead_args.tag.phys_addr,
				    op->op_aead_args.tag.len,
				    flag);
		break;
	default:
		printf("unsupported aead algo %u", op->op_aead_args.algo);
		return -1;
	}

	return 0;
}
