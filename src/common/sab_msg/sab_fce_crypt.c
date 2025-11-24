/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include <stdio.h>

#include "internal/fce.h"
#include "sab_fce_process_msg.h"
#include "sab_fce_auth.h"
#include "sab_fce_aes.h"
#include "fce_uio.h"

int fce_auth_build(crypto_op_args_t *op,
		   uint8_t buf_off,
		   uint8_t flag)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();
	uint32_t *mu_buf = (uint32_t *)(fce_mu->mu_buf + buf_off);

	fce_auth_construct(mu_buf, op->auth.keyslot,
			   op->src.phys_addr, op->src.len,
			   op->auth.digest.phys_addr, op->auth.sha_algo,
			   op->auth.dir, flag);

	return 0;
}

int fce_cipher_build(crypto_op_args_t *op,
		     uint8_t buf_off,
		     uint8_t flag)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();
	uint32_t *mu_buf = (uint32_t *)(fce_mu->mu_buf + buf_off);
	uint32_t digest_addr;
	uint8_t sha_algo;

	if (op->auth.sha_algo != 0) {
		digest_addr = op->auth.digest.phys_addr;
		sha_algo = op->auth.sha_algo;
	} else {
		digest_addr = 0;
		sha_algo = 0;
	}

	switch (op->cipher.algo) {
	case CRYPTO_CIPHER_AES_CBC:
		fce_cbc_construct(mu_buf, op->cipher.keyslot,
				  op->src.phys_addr, op->dst.phys_addr,
				  op->src.len, op->cipher.enc,
				  op->cipher.iv, op->cipher.ivlen,
				  digest_addr, sha_algo, flag);
		break;
	case CRYPTO_CIPHER_AES_ECB:
		fce_ecb_construct(mu_buf, op->cipher.keyslot,
				  op->src.phys_addr, op->dst.phys_addr,
				  op->src.len, op->cipher.enc,
				  digest_addr, sha_algo, flag);
		break;
	default:
		printf("unsupported cipher algo %u", op->cipher.algo);
		return -1;
	}

	return 0;
}

int fce_aead_build(crypto_op_args_t *op,
		   uint8_t buf_off,
		   uint8_t flag)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();
	uint32_t *mu_buf = (uint32_t *)(fce_mu->mu_buf + buf_off);

	switch (op->aead.algo) {
	case CRYPTO_AEAD_AES_GCM:
		fce_gcm_construct(mu_buf, op->aead.keyslot,
				  op->src.phys_addr, op->dst.phys_addr,
				  op->src.len, op->aead.enc,
				  op->aead.iv, op->aead.ivlen,
				  op->aead.aad.phys_addr, op->aead.aad.len,
				  op->aead.tag.phys_addr, op->aead.tag.len,
				  flag);
		break;
	default:
		printf("unsupported aead algo %u", op->aead.algo);
		return -1;
	}

	return 0;
}
