// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "prime.h"
#include "uio.h"

#include "include/mem.h"
#include "include/test_prime_utils.h"
#include "include/aes_ecb_test_vector.h"
#include "include/aes_cbc_test_vector.h"
#include "include/aes_ctr_test_vector.h"

static uint8_t *plaintext;
static uint8_t *ciphertext;

static int generate_test_pattern(uint32_t len)
{
	uint32_t i;

	plaintext = malloc(len);
	if (!plaintext) {
		printf("Failed to alloc memory for ptext (%u bytes)\n", len);
		return -1;
	}

	ciphertext = malloc(len);
	if (!ciphertext) {
		printf("Failed to alloc memory for ctext (%u bytes)\n", len);
		free(plaintext);
		plaintext = NULL;
		return -1;
	}

	/* Generate pseudo-random plaintext pattern */
	for (i = 0; i < len; i++)
		plaintext[i] = (uint8_t)((i * 7 + 13) & 0xFF);

	for (i = 0; i < len; i++)
		ciphertext[i] = (uint8_t)((i * 11 + 17) ^ 0xAA);

	return 0;
}

static void free_test_pattern(void)
{
	if (plaintext) {
		free(plaintext);
		plaintext = NULL;
	}
	if (ciphertext) {
		free(ciphertext);
		ciphertext = NULL;
	}
}

static void complete_aes_ops(crypto_op_args_t **ops, uint32_t nb_ops)
{
	uint32_t i;

	for (i = 0; i < nb_ops; i++)
		data_cache_clean(ops[i]->dst.virt_addr, ops[i]->dst.len, 0);
}

static int aes_load_key(aes_key_t *key_args, uint8_t *key, uint32_t keylen)
{
	key_args->key = key;
	key_args->keylen = keylen;
	key_args->keyslot = 0;

	return prime_cipher_init(key_args);
}

static int validate_aes_op(crypto_op_args_t *op, uint8_t *test_vec)
{
	if (prime_mcompare(op->dst.virt_addr, test_vec, op->dst.len))
		return -1;
	return 0;
}

static void prepare_aes_op(uint32_t service_hdl, crypto_op_args_t *op,
			   uint8_t *test_vec, uint32_t len,
			   int algo, uint8_t keyslot, int enc,
			   uint8_t *iv, uint16_t ivlen, void *va, uint64_t phys)
{
	uint64_t status_offset;

	op->src.len = len;
	op->src.virt_addr = (uint8_t *)va;
	op->src.phys_addr = phys;

	/* output buffer */
	op->dst.len = op->src.len;
	op->dst.virt_addr = op->src.virt_addr;
	op->dst.phys_addr = op->src.phys_addr;

	/* copy the test vector & cache clean */
	prime_mcopy(op->src.virt_addr, test_vec, op->src.len);
	data_cache_clean(op->src.virt_addr, op->src.len, 1);

	/* prepare op args */
	op->op_type = CRYPTO_OP_TYPE_AES;
	op->op_aes_args.algo = algo;
	op->op_aes_args.keyslot = keyslot;
	op->op_aes_args.enc = enc;
	op->op_aes_args.iv = iv;
	op->op_aes_args.ivlen = ivlen;
	status_offset = ALIGN_UP(len, 64);
	op->crypto_status.phys_addr =
		(status_buf_t *)(op->src.phys_addr + status_offset);
	op->crypto_status.virt_addr =
		(status_buf_t *)(op->src.virt_addr + status_offset);
}

int aes_ctr_test_8192(uint32_t service_hdl, aes_key_t *key_args, void *va, uint64_t phys)
{
	crypto_op_args_t op[2] = {0};
	crypto_op_args_t *ops_ptr;
	uint32_t nb_ops;
	int32_t err;

	/* Generate test patterns */
	err = generate_test_pattern(8192);
	if (err) {
		printf("Failed to generate test patterns\n");
		return err;
	}

	/* ========== Encryption ========== */
	/* prepare op */
	prepare_aes_op(service_hdl, &op[0],
		       plaintext, 8192,
		       CRYPTO_CIPHER_AES_CTR, key_args->keyslot,
		       CRYPTO_CIPHER_OP_ENCRYPT,
		       ctr, sizeof(ctr), va, phys);

	/* fill ops array */
	ops_ptr = &op[0];
	nb_ops = 1;

	/* invoke fast crypto engine */
	err = prime_process_ops(service_hdl, &ops_ptr, nb_ops);
	if (err) {
		free_test_pattern();
		return err;
	}

	/* complete operation */
	complete_aes_ops(&ops_ptr, nb_ops);

	/* ========== Decryption ========== */
	prime_mcopy(ciphertext, op[0].dst.virt_addr,  op[0].dst.len);

	/* prepare op */
	prepare_aes_op(service_hdl, &op[1],
		       ciphertext, 8192,
		       CRYPTO_CIPHER_AES_CTR, key_args->keyslot,
		       CRYPTO_CIPHER_OP_DECRYPT,
		       ctr, sizeof(ctr), va, phys);

	ops_ptr = &op[1];
	nb_ops = 1;

	/* invoke fast crypto engine */
	err = prime_process_ops(service_hdl, &ops_ptr, nb_ops);
	if (err) {
		free_test_pattern();
		return err;
	}

	/* complete operation */
	complete_aes_ops(&ops_ptr, nb_ops);

	/* compare output data */
	if (validate_aes_op(&op[1], plaintext)) {
		printf("AES-256-CTR(%dB) test failed\n", op[1].dst.len);
		free_test_pattern();
		return -1;
	}

	/* free test patterns */
	free_test_pattern();
	return 0;
}

int aes_ctr_test_256(uint32_t service_hdl, aes_key_t *key_args, void *va, uint64_t phys)
{
	crypto_op_args_t op = {0};
	crypto_op_args_t *ops_ptr;
	uint32_t nb_ops;
	int32_t err;

	/* prepare op */
	prepare_aes_op(service_hdl, &op,
		       ctr_plain_256, sizeof(ctr_plain_256),
		       CRYPTO_CIPHER_AES_CTR, key_args->keyslot,
		       CRYPTO_CIPHER_OP_ENCRYPT,
		       ctr, sizeof(ctr), va, phys);

	/* fill ops array */
	ops_ptr = &op;
	nb_ops = 1;

	/* invoke fast crypto engine */
	err = prime_process_ops(service_hdl, &ops_ptr, nb_ops);
	if (err)
		return err;

	/* complete execution and free memory */
	complete_aes_ops(&ops_ptr, nb_ops);

	/* compare output data */
	if (validate_aes_op(&op, ctr_cipher_256)) {
		printf("AES-256-CTR(%dB) test failed\n", op.dst.len);
		return -1;
	}

	return 0;
}

int aes_ctr_test(uint32_t service_hdl, void *va, uint64_t phys)
{
	aes_key_t key_args = {0};
	int32_t err;

	/* load aes key */
	err = aes_load_key(&key_args, ctr_key, sizeof(ctr_key));
	if (err) {
		printf("Failed to load AES-CTR key (256B)\n");
		return err;
	}

	/* Test with 256 bytes */
	err = aes_ctr_test_256(service_hdl, &key_args, va, phys);
	if (err)
		return err;

	/* Test with 8192 bytes */
	err = aes_ctr_test_8192(service_hdl, &key_args, va, phys);
	if (err)
		return err;

	return 0;
}

int aes_cbc_test(uint32_t service_hdl, void *va, uint64_t phys)
{
	aes_key_t key_args = {0};
	crypto_op_args_t op = {0};
	crypto_op_args_t *ops_ptr;
	uint32_t nb_ops;
	int32_t err;

	/* load aes key */
	err = aes_load_key(&key_args, cbc_key, sizeof(cbc_key));
	if (err)
		return err;

	/* prepare op */
	prepare_aes_op(service_hdl, &op,
		       cbc_plain, sizeof(cbc_plain),
		       CRYPTO_CIPHER_AES_CBC, key_args.keyslot,
		       CRYPTO_CIPHER_OP_ENCRYPT,
		       iv, sizeof(iv), va, phys);

	/* fill ops array */
	ops_ptr = &op;
	nb_ops = 1;

	/* invoke fast crypto engine */
	err = prime_process_ops(service_hdl, &ops_ptr, nb_ops);
	if (err)
		return err;

	/* complete execution and free memory */
	complete_aes_ops(&ops_ptr, nb_ops);

	/* compare output data */
	if (validate_aes_op(&op, cbc_cipher)) {
		printf("AES-256-CBC(%dB) test failed\n", op.dst.len);
		return -1;
	}

	return 0;
}

int aes_ecb_test(uint32_t service_hdl, void *va, uint64_t phys)
{
	aes_key_t key_args = {0};
	crypto_op_args_t op = {0};
	crypto_op_args_t *ops_ptr;
	uint32_t nb_ops;
	int32_t err;

	/* load aes key */
	err = aes_load_key(&key_args, ecb_key, sizeof(ecb_key));
	if (err)
		return err;

	/* prepare op */
	prepare_aes_op(service_hdl, &op,
		       ecb_plain, sizeof(ecb_plain),
		       CRYPTO_CIPHER_AES_ECB, key_args.keyslot,
		       CRYPTO_CIPHER_OP_ENCRYPT,
		       NULL, 0, va, phys);

	/* fill ops array */
	ops_ptr = &op;
	nb_ops = 1;

	/* invoke fast crypto engine */
	err = prime_process_ops(service_hdl, &ops_ptr, nb_ops);
	if (err)
		return err;

	/* complete execution and free memory */
	complete_aes_ops(&ops_ptr, nb_ops);

	/* compare output data */
	if (validate_aes_op(&op, ecb_cipher)) {
		printf("AES-256-ECB(%dB) test failed\n", op.dst.len);
		return -1;
	}

	return 0;
}
