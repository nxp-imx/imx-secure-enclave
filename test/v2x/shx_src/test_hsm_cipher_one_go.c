// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_cipher_one_go.h"
#ifdef USE_SSL
#include <openssl/evp.h>
#endif

#define CCM_IV_SIZE 12

uint32_t test_hsm_cipher_one_go(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;
	uint32_t key_id_number;
	uint8_t cipher_store_index;
	uint8_t *input_ptr;    // To simplify buffer freeing logic
	op_cipher_one_go_args_t args;
	uint8_t *iv_buffer;

	// read the cipher index.
	index                    = READ_VALUE(fp, uint32_t);
	key_id_number            = READ_VALUE(fp, uint32_t);
	if (key_id_number == BAD_VAL) {
		args.key_identifier = BAD_VAL;
	} else if (!testCtx->key_id[key_id_number]) {
		args.key_identifier = BAD_VAL;
		slt_print(SLT_WARNING, "Saw invalid key id pointer\n");
	} else {
		args.key_identifier = *testCtx->key_id[key_id_number];
		slt_print(SLT_INFO, "key id 0x%x\n", args.key_identifier);
	}

	cipher_store_index       = READ_VALUE(fp, uint8_t);
	args.iv_size             = READ_VALUE(fp, uint16_t);
	iv_buffer                = READ_INPUT_BUFFER(fp, args.iv_size);
	args.iv                  = iv_buffer;
	args.cipher_algo         = READ_VALUE(fp, hsm_op_cipher_one_go_algo_t);
	args.flags               = READ_VALUE(fp, hsm_op_cipher_one_go_flags_t);

	/* Get input and input size
	 * But for DECRYPT case we replace it by:
	 * - Addr = 0xBADBAD (size: 0) if specific cipher_store_index=0xBADBAD is used
	 * - Addr/size taken from internal array (if previously filled by ENCRYPT process)
	 */
	args.input_size          = READ_VALUE(fp, uint32_t);
	input_ptr                = READ_INPUT_BUFFER(fp, args.input_size);
	args.input               = input_ptr;

	if ((args.flags & 0x01) == HSM_CIPHER_ONE_GO_FLAGS_DECRYPT) { /* DECRYPT */
		if (cipher_store_index == BAD_VAL) {
			args.input               = (uint8_t *)BAD_VAL;
			args.input_size          = 0;
		} else if (args.input_size == 0) {
			args.input      = testCtx->cipher_ptr[cipher_store_index];
			if (args.cipher_algo == HSM_CIPHER_ONE_GO_ALGO_AES_CCM) {
				args.input_size =
					testCtx->cipher_size[cipher_store_index]
					- CCM_IV_SIZE;
				args.iv         = args.input + args.input_size;
				args.iv_size    = CCM_IV_SIZE;
			} else {
				args.input_size =
					testCtx->cipher_size[cipher_store_index];
			}
		}
	}

	args.output_size         = READ_VALUE(fp, uint32_t);
	args.output              = READ_INPUT_BUFFER(fp, args.output_size);

	hsm_err_t err = hsm_cipher_one_go(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);

	if ((args.flags & 0x01) == HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT) { /* ENCRYPT */
		testCtx->cipher_size[cipher_store_index] = args.output_size;
		testCtx->cipher_ptr[cipher_store_index] = args.output;
	}

#ifdef CAVP_SUPPORT
	if (args.cipher_algo == HSM_CIPHER_ONE_GO_ALGO_AES_CCM) {
		if (err == HSM_GENERAL_ERROR) {
			slt_print(SLT_ERROR, "<OUTPUT_DATA>\nFAIL\n</OUTPUT_DATA>\n");
			slt_print(SLT_ERROR, "<OUTPUT_DATA>\n</OUTPUT_DATA>\n");
		} else {
			slt_print(SLT_NOTICE, "<OUTPUT_DATA>\nPASS\n</OUTPUT_DATA>\n");
			DISPLAY_BUFFER(args.output, args.output_size);
		}
	} else {
		DISPLAY_BUFFER(args.output, args.output_size);
	}
#endif
	READ_CHECK_BUFFER(testCtx, fp, args.output, args.output_size);

	if (iv_buffer)
		FREE_BUFFER(iv_buffer);
	if (input_ptr)
		FREE_BUFFER(input_ptr);

	if ((args.flags & 0x01) == HSM_CIPHER_ONE_GO_FLAGS_DECRYPT)
		FREE_BUFFER(args.output);

	return fails;
}

#ifdef USE_SSL
uint32_t test_hsm_verify_cipher_one_go_ccm_encryption(hsm_test_struct_t *testCtx,
						      FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;
	uint32_t key_id_number;
	uint8_t cipher_store_index;
	op_cipher_one_go_args_t args;
	uint8_t *iv_buffer;
	EVP_CIPHER_CTX *ctx;
	uint32_t key_size;
	uint8_t *key_data;
	uint8_t *ciphertext;
	uint32_t cipherlen;
	uint8_t *tag;

	// read the cipher index.
	index                    = READ_VALUE(fp, uint32_t);
	key_id_number            = READ_VALUE(fp, uint32_t);
	if (!testCtx->key_id[key_id_number]) {
		slt_print(SLT_ERROR, "Saw invalid key id pointer\n");
		return 1;
	}
	args.key_identifier = *testCtx->key_id[key_id_number];

	cipher_store_index       = READ_VALUE(fp, uint8_t);
	args.iv_size             = READ_VALUE(fp, uint16_t);
	iv_buffer                = READ_INPUT_BUFFER(fp, args.iv_size);
	args.iv                  = iv_buffer;
	args.cipher_algo         = READ_VALUE(fp, hsm_op_cipher_one_go_algo_t);
	args.flags               = READ_VALUE(fp, hsm_op_cipher_one_go_flags_t);

	args.input_size          = READ_VALUE(fp, uint32_t);
	args.input               = READ_INPUT_BUFFER(fp, args.input_size);

	key_size                 = READ_VALUE(fp, uint32_t);
	key_data                 = READ_INPUT_BUFFER(fp, key_size);

	if ((args.flags & 0x01) == HSM_CIPHER_ONE_GO_FLAGS_DECRYPT) { /* DECRYPT */
		slt_print(SLT_ERROR, "Auth_enc verification only verifies encryption\n");
		return 1;
	}

	args.output_size         = args.input_size + 16 + 12;
	args.output              = malloc(args.output_size);

	hsm_err_t err = hsm_cipher_one_go(testCtx->hdl[index], &args);

	DISPLAY_BUFFER(args.iv, args.iv_size);
	DISPLAY_BUFFER(args.output, args.output_size);

	READ_CHECK_VALUE(testCtx, fp, err);

	if (err == HSM_NO_ERROR) {
		/* Calculated expected output based on received IV */
		ciphertext = malloc(args.input_size);
		tag = malloc(16);
		ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
			slt_print(SLT_ERROR, "Error creating cipher context\n");
			return 1;
		}
		switch (key_size) {
		case 16:
			if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(),
					       NULL, NULL, NULL) != 1) {
				slt_print(SLT_ERROR, "Error initializing AES_128_ccm\n");
				return 1;
			}
			break;
		case 24:
			if (EVP_EncryptInit_ex(ctx, EVP_aes_192_ccm(),
					       NULL, NULL, NULL) != 1) {
				slt_print(SLT_ERROR, "Error initializing AES_192_ccm\n");
				return 1;
			}
			break;
		case 32:
			if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(),
					       NULL, NULL, NULL) != 1) {
				slt_print(SLT_ERROR, "Error initializing AES_256_ccm\n");
				return 1;
			}
			break;
		default:
			slt_print(SLT_ERROR, "Invalid key size\n");
			return 1;
		}

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, NULL) != 1) {
			slt_print(SLT_ERROR, "Error setting tag length\n");
			return 1;
		}

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 12, NULL) != 1) {
			slt_print(SLT_ERROR, "Error setting IV length\n");
			return 1;
		}

		if (EVP_EncryptInit_ex(ctx, NULL, NULL, key_data,
				       args.output + args.input_size + 16) != 1) {
			slt_print(SLT_ERROR, "Error initializing key & IV\n");
			return 1;
		}

		if (EVP_EncryptUpdate(ctx, ciphertext, &cipherlen,
				      args.input, args.input_size) != 1) {
			slt_print(SLT_ERROR, "Error processing plaintext\n");
			return 1;
		}
		if (cipherlen != args.input_size) {
			slt_print(SLT_ERROR, "Unexpected ciphertext length\n");
			return 1;
		}

		if (EVP_EncryptFinal_ex(ctx, ciphertext + cipherlen, &cipherlen) != 1) {
			slt_print(SLT_ERROR, "Error finalizing ciphertext\n");
			return 1;
		}
		if (cipherlen != 0) {
			slt_print(SLT_ERROR, "Unexpected extra ciphertext\n");
			return 1;
		}

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 16, tag) != 1) {
			slt_print(SLT_ERROR, "Error retrieving tag\n");
			return 1;
		}

		EVP_CIPHER_CTX_free(ctx);

		CHECK_BUFFER(testCtx, args.output, ciphertext, args.input_size);
		CHECK_BUFFER(testCtx, (args.output + args.input_size), tag, 16);
	}

	testCtx->cipher_size[cipher_store_index] = args.output_size;
	testCtx->cipher_ptr[cipher_store_index] = args.output;

	if (iv_buffer)
		free(iv_buffer);
	if (key_data)
		free(key_data);
	if (ciphertext)
		free(ciphertext);
	if (tag)
		free(tag);

	return fails;
}
#else
uint32_t test_hsm_verify_cipher_one_go_ccm_encryption(hsm_test_struct_t *testCtx,
						      FILE *fp)
{
	slt_print(SLT_ERROR, "Error: Need to compile with SSL support\n");
	return 1;
}
#endif
