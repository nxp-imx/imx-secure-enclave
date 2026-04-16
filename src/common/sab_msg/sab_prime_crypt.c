/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>

#include "prime.h"
#include "sab_prime_process_msg.h"
#include "sab_prime_auth.h"
#include "sab_prime_aes.h"
#include "uio.h"

static int32_t get_inbound_addr(prime_service_t *hdl, uint64_t phys_addr,
				uint32_t len, uint32_t *inbound_addr)
{
	/* If 32-bit address, use it directly */
	if ((phys_addr >> 32) == 0) {
		*inbound_addr = (uint32_t)phys_addr;
		return 0;
	}

	if (phys_addr < hdl->physical_addr ||
	    (phys_addr + len) > (hdl->physical_addr + hdl->size)) {
		printf("Physical address is not owned by requestor\n");
		return -1;
	}

	*inbound_addr = (hdl->inbound_addr + (phys_addr - hdl->physical_addr));
	return 0;
}

int prime_auth_build(prime_service_t *hdl,
		     crypto_op_args_t *op,
		     uint8_t buf_off,
		     uint8_t flag)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();
	uint32_t *mu_buf = (uint32_t *)(prime_mu->mu_buf + buf_off);
	uint32_t inbound_src_addr, inbound_digest_addr;

	if (get_inbound_addr(hdl, op->src.phys_addr, op->src.len, &inbound_src_addr) < 0)
		return -1;

	if (get_inbound_addr(hdl, op->op_auth_args.digest.phys_addr,
			     op->op_auth_args.digest.len, &inbound_digest_addr) < 0)
		return -1;

	prime_auth_construct(mu_buf, op->op_auth_args.keyslot,
			     inbound_src_addr, op->src.len,
			     inbound_digest_addr, op->op_auth_args.sha_algo,
			     op->op_auth_args.dir, flag);
	return 0;
}

int prime_cipher_build(prime_service_t *hdl,
		       crypto_op_args_t *op,
		       uint8_t buf_off,
		       uint8_t flag)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();
	uint32_t *mu_buf = (uint32_t *)(prime_mu->mu_buf + buf_off);
	uint32_t digest_addr = 0;
	uint8_t sha_algo = 0;
	uint32_t inbound_src_addr, inbound_dst_addr;

	if (get_inbound_addr(hdl, op->src.phys_addr, op->src.len, &inbound_src_addr) < 0)
		return -1;

	if (get_inbound_addr(hdl, op->dst.phys_addr, op->dst.len, &inbound_dst_addr) < 0)
		return -1;

	switch (op->op_aes_args.algo) {
	case CRYPTO_CIPHER_AES_CBC:
		prime_cbc_construct(mu_buf, op->op_aes_args.keyslot,
				    inbound_src_addr, inbound_dst_addr,
				    op->src.len, op->op_aes_args.enc,
				    op->op_aes_args.iv, op->op_aes_args.ivlen,
				    digest_addr, sha_algo, flag);
		break;
	case CRYPTO_CIPHER_AES_ECB:
		prime_ecb_construct(mu_buf, op->op_aes_args.keyslot,
				    inbound_src_addr, inbound_dst_addr,
				    op->src.len, op->op_aes_args.enc,
				    digest_addr, sha_algo, flag);
		break;
	case CRYPTO_CIPHER_AES_CTR:
		prime_ctr_construct(mu_buf, op->op_aes_args.keyslot,
				    inbound_src_addr, inbound_dst_addr,
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

int prime_aead_build(prime_service_t *hdl,
		     crypto_op_args_t *op,
		     uint8_t buf_off,
		     uint8_t flag)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();
	uint32_t *mu_buf = (uint32_t *)(prime_mu->mu_buf + buf_off);
	uint32_t inbound_src_addr, inbound_dst_addr;
	uint32_t inbound_aad_addr, inbound_tag_addr;

	if (get_inbound_addr(hdl, op->src.phys_addr, op->src.len, &inbound_src_addr) < 0)
		return -1;

	if (get_inbound_addr(hdl, op->dst.phys_addr, op->dst.len, &inbound_dst_addr) < 0)
		return -1;

	if (get_inbound_addr(hdl, op->op_aead_args.aad.phys_addr,
			     op->op_aead_args.aad.len, &inbound_aad_addr) < 0)
		return -1;

	if (get_inbound_addr(hdl, op->op_aead_args.tag.phys_addr,
			     op->op_aead_args.tag.len, &inbound_tag_addr) < 0)
		return -1;

	switch (op->op_aead_args.algo) {
	case CRYPTO_AEAD_AES_GCM:
		prime_gcm_construct(mu_buf, op->op_aead_args.keyslot,
				    inbound_src_addr, inbound_dst_addr,
				    op->src.len, op->op_aead_args.enc,
				    op->op_aead_args.iv, op->op_aead_args.ivlen,
				    inbound_aad_addr,
				    op->op_aead_args.aad.len,
				    inbound_tag_addr,
				    op->op_aead_args.tag.len,
				    flag);
		break;
	default:
		printf("unsupported aead algo %u", op->op_aead_args.algo);
		return -1;
	}

	return 0;
}
