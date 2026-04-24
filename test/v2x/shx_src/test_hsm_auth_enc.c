// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_auth_enc.h"
#ifdef USE_SSL
#include <openssl/evp.h>
#endif

#define GCM_IV_SIZE 12

uint32_t test_hsm_auth_enc(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;
	uint32_t key_id_number;
	uint8_t store_ind;
	op_auth_enc_args_t args;
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
		// key gen cmd to be executed before
		args.key_identifier = *testCtx->key_id[key_id_number];
	}

	store_ind     = READ_VALUE(fp, uint8_t);
	args.iv_size             = READ_VALUE(fp, uint16_t);
	iv_buffer                = READ_INPUT_BUFFER(fp, args.iv_size);
	args.iv                  = iv_buffer;
	args.aad_size            = READ_VALUE(fp, uint16_t);
	args.aad                 = READ_INPUT_BUFFER(fp, args.aad_size);
	args.ae_algo             = READ_VALUE(fp, hsm_op_auth_enc_algo_t);
	args.flags               = READ_VALUE(fp, hsm_op_auth_enc_flags_t);

	/* Get input and input size
	 * But for DECRYPT case we replace it by:
	 * - Addr = 0xBADBAD (size: 0) if specific cipher_store_ind=0xBADBAD is used
	 * - Addr/size taken from internal array (if previously filled by ENCRYPT process)
	 * NOTE: IV stored at end of buffer
	 */
	args.input_size          = READ_VALUE(fp, uint32_t);
	args.input               = READ_INPUT_BUFFER(fp, args.input_size);

	if ((args.flags & HSM_CIPHER_ONE_GO_MASK_OP_TYPE)
	    == HSM_CIPHER_ONE_GO_FLAGS_DECRYPT) { /* DECRYPT */
		if (store_ind == BAD_VAL) {
			args.input      = (uint8_t *)BAD_VAL;
			args.input_size = 0;
		} else if (args.input_size == 0) {
			args.input     = testCtx->auth_enc_ptr[store_ind];
			args.input_size = testCtx->auth_enc_size[store_ind] - GCM_IV_SIZE;
			args.iv        = args.input + args.input_size;
			args.iv_size   = GCM_IV_SIZE;
		}
	}

	args.output_size         = READ_VALUE(fp, uint32_t);
	args.output              = READ_INPUT_BUFFER(fp, args.output_size);

	hsm_err_t err = hsm_auth_enc(testCtx->hdl[index], &args);

	if ((args.flags & HSM_CIPHER_ONE_GO_MASK_OP_TYPE)
	    == HSM_CIPHER_ONE_GO_FLAGS_DECRYPT) { /* DECRYPT */
		if (err == HSM_GENERAL_ERROR) {
			slt_print(SLT_ERROR, "<OUTPUT_DATA>\nFAIL\n</OUTPUT_DATA>\n");
		} else {
			slt_print(SLT_DEBUG, "<OUTPUT_DATA>\nPASS\n</OUTPUT_DATA>\n");
			DISPLAY_BUFFER(args.output, args.output_size);
		}
#ifdef CAVP_SUPPORT
		// ACVP tests need iv in output data
		slt_print(SLT_NOTICE, "IV:\n");
		DISPLAY_BUFFER(args.iv, args.iv_size);
#endif
	} else if ((args.flags & 0x01) == HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT) {
#ifdef CAVP_SUPPORT
		// ACVP tests need iv in output data
		/* Extract IV from output buffer - always last in buffer */
		DISPLAY_BUFFER(&args.output[args.output_size - GCM_IV_SIZE],
			       GCM_IV_SIZE);
		DISPLAY_BUFFER(args.output, args.output_size - GCM_IV_SIZE);
#endif
	}

	READ_CHECK_VALUE(testCtx, fp, err);

	if ((args.flags & 0x01) == HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT) { /* ENCRYPT */
		testCtx->auth_enc_size[store_ind] = args.output_size;
		testCtx->auth_enc_ptr[store_ind] = args.output;
	}

	READ_CHECK_BUFFER(testCtx, fp, args.output, args.output_size);

	if (iv_buffer)
		free(iv_buffer);
	if (args.aad)
		free(args.aad);
	if (args.flags == 1 && args.input)
		free(args.input);

	return fails;
}

#ifdef USE_SSL
uint32_t test_hsm_verify_auth_encryption(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;
	uint32_t key_id_number;
	uint8_t store_ind;
	op_auth_enc_args_t args;
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
	store_ind       = READ_VALUE(fp, uint8_t);
	args.iv_size    = READ_VALUE(fp, uint16_t);
	iv_buffer       = READ_INPUT_BUFFER(fp, args.iv_size);
	args.iv         = iv_buffer;
	args.aad_size   = READ_VALUE(fp, uint16_t);
	args.aad        = READ_INPUT_BUFFER(fp, args.aad_size);
	args.ae_algo    = READ_VALUE(fp, hsm_op_auth_enc_algo_t);
	args.flags      = READ_VALUE(fp, hsm_op_auth_enc_flags_t);

	args.input_size = READ_VALUE(fp, uint32_t);
	args.input      = READ_INPUT_BUFFER(fp, args.input_size);

	key_size        = READ_VALUE(fp, uint32_t);
	key_data        = READ_INPUT_BUFFER(fp, key_size);

	if ((args.flags & HSM_CIPHER_ONE_GO_MASK_OP_TYPE)
	    == HSM_CIPHER_ONE_GO_FLAGS_DECRYPT) { /* DECRYPT */
		slt_print(SLT_ERROR, "Auth_enc verification only verifies encryption\n");
		return 1;
	}

	args.output_size = args.input_size + 16 + 12;
	args.output      = malloc(args.output_size);

	hsm_err_t err = hsm_auth_enc(testCtx->hdl[index], &args);

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
			if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key_data,
					       args.output + args.input_size + 16)
			    != 1) {
				slt_print(SLT_ERROR, "Error initializing AES_256_gcm\n");
				return 1;
			}
			break;
		case 24:
			if (EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, key_data,
					       args.output + args.input_size + 16)
			    != 1) {
				slt_print(SLT_ERROR, "Error initializing AES_256_gcm\n");
				return 1;
			}
			break;
		case 32:
			if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key_data,
					       args.output + args.input_size + 16)
			    != 1) {
				slt_print(SLT_ERROR, "Error initializing AES_256_gcm\n");
				return 1;
			}
			break;
		default:
			slt_print(SLT_ERROR, "Invalid key size\n");
			return 1;
		}

		if (args.aad_size) {
			if (EVP_EncryptUpdate(ctx, NULL, &cipherlen,
					      args.aad, args.aad_size)
			    != 1) {
				slt_print(SLT_ERROR, "Error processing AAD\n");
				return 1;
			}
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

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
			slt_print(SLT_ERROR, "Error retrieving tag\n");
			return 1;
		}

		EVP_CIPHER_CTX_free(ctx);

		CHECK_BUFFER(testCtx, args.output, ciphertext, args.input_size);
		CHECK_BUFFER(testCtx, (args.output + args.input_size), tag, 16);
	}

	testCtx->auth_enc_size[store_ind] = args.output_size;
	testCtx->auth_enc_ptr[store_ind] = args.output;

	if (iv_buffer)
		free(iv_buffer);
	if (args.aad)
		free(args.aad);
	if (key_data)
		free(key_data);
	if (ciphertext)
		free(ciphertext);
	if (tag)
		free(tag);

	return fails;
}
#else
uint32_t test_hsm_verify_auth_encryption(hsm_test_struct_t *testCtx, FILE *fp)
{
	slt_print(SLT_ERROR, "Error: Need to compile with SSL support\n");
	return 1;
}
#endif
