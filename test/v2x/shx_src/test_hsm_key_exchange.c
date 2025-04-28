// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <unistd.h>
#include <fcntl.h>
#include "hsm_exec.h"
#ifdef USE_SSL
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/param_build.h>
#endif

#define SIGNED_MESSAGE_KEY_EXCHANGE_KEK_GEN_EN_SIZE 0x360

#include "test_hsm_key_exchange.h"

uint32_t test_hsm_key_exchange(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t index;
	uint32_t temp;
	uint32_t ecdh_key_id_number;
	uint32_t number_of_generated_key_index;
	uint32_t *generated_key_id_number;
	op_key_exchange_args_t args;

	index                                   = READ_VALUE(fp, uint32_t);
	ecdh_key_id_number                      = READ_VALUE(fp, uint32_t);

	number_of_generated_key_index           = READ_VALUE(fp, uint32_t);
	args.shared_key_identifier_array_size   = sizeof(uint32_t) *
							number_of_generated_key_index;
	generated_key_id_number = malloc(args.shared_key_identifier_array_size);
	for (uint8_t i = 0; i < number_of_generated_key_index; i++)
		generated_key_id_number[i] = READ_VALUE(fp, uint32_t);

	args.ke_input_size  = READ_VALUE(fp, uint16_t);
	args.ke_input       = READ_INPUT_BUFFER(fp, args.ke_input_size);

	args.ke_output_size = READ_VALUE(fp, uint16_t);
	args.ke_output      = READ_OUTPUT_BUFFER(fp, args.ke_output_size);

	args.kdf_input_size  = READ_VALUE(fp, uint16_t);
	args.kdf_input       = READ_INPUT_BUFFER(fp, args.kdf_input_size);

	args.kdf_output_size = READ_VALUE(fp, uint16_t);
	args.kdf_output      = READ_OUTPUT_BUFFER(fp, args.kdf_output_size);

	args.shared_key_group           = READ_VALUE(fp, uint16_t);
	args.shared_key_info            = READ_VALUE(fp, uint16_t);
	args.shared_key_type            = READ_VALUE(fp, uint16_t);
	args.initiator_public_data_type = READ_VALUE(fp, uint16_t);
	args.key_exchange_scheme        = READ_VALUE(fp, uint16_t);
	args.kdf_algorithm              = READ_VALUE(fp, uint16_t);
	args.flags                      = READ_VALUE(fp, uint16_t);
	args.signed_message = NULL;
	args.signed_msg_size = 0;

	//must be zero if HSM_OP_KEY_EXCHANGE_FLAGS_USE_EPHEMERAL is set
	if (ecdh_key_id_number == BAD_0)
		args.key_identifier = 0;
	else if (ecdh_key_id_number == BAD_VAL)
		args.key_identifier = BAD_VAL;
	else
		args.key_identifier = *testCtx->key_id[ecdh_key_id_number];

	if (args.flags & HSM_OP_KEY_EXCHANGE_FLAGS_UPDATE) {
		if (generated_key_id_number[0] == BAD_0) {  // Addr = 0x0
			args.shared_key_identifier_array       = 0x0;
		} else if (generated_key_id_number[0] == BAD_1) {  // Addr = 0xBADBAD
			args.shared_key_identifier_array       = (uint8_t *)BAD_ADDR;
		} else {
			args.shared_key_identifier_array =
				malloc(args.shared_key_identifier_array_size);
			for (uint8_t i = 0; i < number_of_generated_key_index; i++) {
				temp = i * sizeof(uint32_t);
				*(uint32_t *)(&args.shared_key_identifier_array[temp]) =
					*testCtx->key_id[generated_key_id_number[i]];
			}
		}
	} else {
		args.shared_key_identifier_array =
			malloc(args.shared_key_identifier_array_size);
	}

	hsm_err_t err = hsm_key_exchange(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);

	READ_CHECK_BUFFER(testCtx, fp, args.ke_output, args.ke_output_size);
	READ_CHECK_BUFFER(testCtx, fp, args.kdf_output, args.kdf_output_size);

	if (err == HSM_NO_ERROR) {
		/* Store Key_id address */
		for (uint8_t i = 0; i < number_of_generated_key_index; i++) {
			testCtx->key_id[generated_key_id_number[i]] =
				(uint32_t *)(args.shared_key_identifier_array + (i * 4));
			testCtx->key_group[generated_key_id_number[i]] =
				args.shared_key_group;
		}
		DISPLAY_BUFFER(args.ke_output, args.ke_output_size);
		DISPLAY_BUFFER(args.shared_key_identifier_array,
			       args.shared_key_identifier_array_size);
	} else {
		if (!(args.flags & HSM_OP_KEY_GENERATION_FLAGS_UPDATE))
			FREE_BUFFER(args.shared_key_identifier_array);
	}

	FREE_BUFFER(generated_key_id_number);
	FREE_BUFFER(args.ke_input);
	FREE_BUFFER(args.ke_output);
	FREE_BUFFER(args.kdf_input);
	FREE_BUFFER(args.kdf_output);

	return fails;
}

#ifdef USE_SSL
uint32_t test_hsm_full_key_exchange_sha_kek(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	hsm_err_t err;
	hsm_err_t expected_return;

	uint32_t index;
	uint32_t kek_id_number;
	uint32_t key_group;
	uint8_t *kek_data = NULL;

	EVP_PKEY *local_key = NULL;
	uint8_t local_pub_key[65];
	uint8_t remote_pub_key[65];
	size_t local_pub_key_len;
	EC_GROUP *local_group = NULL;
	EC_POINT *local_point = NULL;
	BIGNUM *local_priv_bn = NULL;

	EVP_PKEY_CTX *remote_ctx = NULL;
	EVP_PKEY_CTX *local_ctx = NULL;
	EVP_PKEY *remote_key = NULL;
	OSSL_PARAM_BLD *remote_params_bld = NULL;
	OSSL_PARAM *remote_params = NULL;

	uint32_t temp_kek_handle;
	op_key_exchange_args_t ke_args;

	uint8_t ecdh_secret[32];
	size_t ecdh_secret_len;
	uint8_t kdf_input[63];
	char FixedInfo[] = "NXP HSM USER KEY DERIVATION";
	EVP_MD_CTX *kdf_context = NULL;
	uint8_t negotiated_kek[32];
	uint32_t key_size;
	hsm_key_exchange_scheme_id_t key_exchange_scheme;
	hsm_key_type_t initiator_public_data_type;
	char *ssl_curve;
	int curve_NID;
	char *file = "/etc/seco_hsm/key_exchange_kek_gen_en_sign_msg.bin";
	int32_t fd = -1;
	int32_t l = 0;

	uint8_t enc_kek[12 + 48] = {0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B };
	EVP_CIPHER_CTX *cipher_ctx = NULL;
	uint32_t enc_len;

	op_manage_key_args_t manage_args;
	uint8_t *signed_message = malloc(SIGNED_MESSAGE_KEY_EXCHANGE_KEK_GEN_EN_SIZE);

	index                                   = READ_VALUE(fp, uint32_t);
	kek_id_number                           = READ_VALUE(fp, uint32_t);
	key_group                               = READ_VALUE(fp, uint16_t);
	initiator_public_data_type              = READ_VALUE(fp, uint8_t);
	key_exchange_scheme                     = READ_VALUE(fp, uint8_t);
	kek_data                                = READ_INPUT_BUFFER(fp, 32);
	expected_return                         = READ_VALUE(fp, hsm_err_t);

	switch (initiator_public_data_type) {
	case HSM_KEY_TYPE_ECDSA_NIST_P256:
		ssl_curve = "P-256";
		curve_NID = NID_X9_62_prime256v1;
		break;

	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256:
		ssl_curve = "brainpoolP256r1";
		curve_NID = NID_brainpoolP256r1;
		break;

	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256:
		ssl_curve = "brainpoolP256t1";
		curve_NID = NID_brainpoolP256t1;
		break;

	default:
		slt_print(SLT_ERROR, "Public data type not implemented: 0x%x\n",
			  initiator_public_data_type);
		fails = 1;
		goto exit;
	}

	/* Generate local key pair */
	local_key = EVP_EC_gen(ssl_curve);
	if (!local_key) {
		slt_print(SLT_ERROR, "Error creating local key\n");
		fails = 1;
		goto exit;
	}

	local_pub_key_len = sizeof(local_pub_key);

#ifdef PKEY
	if (EVP_PKEY_get_octet_string_param(local_key,
					    "pub", local_pub_key,
					    local_pub_key_len,
					    &local_pub_key_len) != 1) {
		slt_print(SLT_ERROR, "Error getting local public key\n");
		fails = 1;
		goto exit;
	}
	if (local_pub_key_len != 65) {
		slt_print(SLT_ERROR, "Unexpected local pub key length: %ld\n",
			  local_pub_key_len);
		fails = 1;
		goto exit;
	}
#else
	local_group = EC_GROUP_new_by_curve_name(curve_NID);
	if (!local_group) {
		slt_print(SLT_ERROR, "Error creating local group\n");
		fails = 1;
		goto exit;
	}

	local_point = EC_POINT_new(local_group);
	if (!local_point) {
		slt_print(SLT_ERROR, "Error creating local point\n");
		fails = 1;
		goto exit;
	}

	if (EVP_PKEY_get_bn_param(local_key, "priv", &local_priv_bn) != 1) {
		slt_print(SLT_ERROR, "Error getting local priv bn\n");
		fails = 1;
		goto exit;
	}

	if (EC_POINT_mul(local_group, local_point,
			 local_priv_bn, NULL, NULL, NULL) != 1) {
		slt_print(SLT_ERROR, "Error doing local point mult\n");
		fails = 1;
		goto exit;
	}

	if (EC_POINT_point2oct(local_group, local_point,
			       POINT_CONVERSION_UNCOMPRESSED,
			       local_pub_key, sizeof(local_pub_key),
			       NULL) != 65) {
		slt_print(SLT_ERROR, "Error extracting local pub key\n");
		fails = 1;
		goto exit;
	}
#endif

	/* Perform key exchange in hsm to get intermediate kek */
	ke_args.key_identifier                   = 0;

	ke_args.shared_key_identifier_array_size = sizeof(uint32_t);
	ke_args.shared_key_identifier_array      = (uint8_t *)&temp_kek_handle;

	ke_args.ke_input_size                    = 64;
	ke_args.ke_input                         = &local_pub_key[1];

	ke_args.ke_output_size                   = 64;
	ke_args.ke_output                        = &remote_pub_key[1];

	ke_args.kdf_input_size                   = 0;
	ke_args.kdf_input                        = 0;

	ke_args.kdf_output_size                  = 0;
	ke_args.kdf_output                       = 0;

	ke_args.shared_key_group                 = key_group;
	ke_args.shared_key_info                  = 0x0A /* Transient KEK */;
	ke_args.shared_key_type                  = HSM_KEY_TYPE_AES_256;
	ke_args.initiator_public_data_type       = initiator_public_data_type;
	ke_args.key_exchange_scheme              = key_exchange_scheme;
	ke_args.kdf_algorithm                    = HSM_KDF_ONE_STEP_SHA_256;
	ke_args.flags                            = 6 /* Create + Ephemeral */;
	ke_args.signed_message = NULL;
	ke_args.signed_msg_size = 0;

	fd = open(file, O_RDONLY);
	if (fd >= 0) {
		l = (int32_t)read(fd, signed_message,
				  SIGNED_MESSAGE_KEY_EXCHANGE_KEK_GEN_EN_SIZE);
		if (l == SIGNED_MESSAGE_KEY_EXCHANGE_KEK_GEN_EN_SIZE) {
			ke_args.signed_message = signed_message;
			ke_args.signed_msg_size =
				SIGNED_MESSAGE_KEY_EXCHANGE_KEK_GEN_EN_SIZE;
		}
	}
	if (!ke_args.signed_message)
		slt_print(SLT_WARNING, "Signed message not sent 0x%x\n", l);

	(void)close(fd);

	err = hsm_key_exchange(testCtx->hdl[index], &ke_args);

	if (err != HSM_NO_ERROR) {
		if (err != expected_return) {
			slt_print(SLT_ERROR, "Error from hsm for key exchange: 0x%x\n",
				  err);
			fails = 1;
		}
		goto exit;
	}
	remote_pub_key[0] = 0x04;

	remote_params_bld = OSSL_PARAM_BLD_new();
	if (!remote_params_bld) {
		slt_print(SLT_ERROR, "Error creating parameter structure\n");
		fails = 1;
		goto exit;
	}

	if (OSSL_PARAM_BLD_push_utf8_string(remote_params_bld,
					    "group", ssl_curve, 0) != 1) {
		slt_print(SLT_ERROR, "Error setting curve parameter\n");
		fails = 1;
		goto exit;
	}

	if (OSSL_PARAM_BLD_push_octet_string(remote_params_bld, "pub",
					     remote_pub_key,
					     sizeof(remote_pub_key)) != 1) {
		slt_print(SLT_ERROR, "Error setting curve parameter\n");
		fails = 1;
		goto exit;
	}

	remote_params = OSSL_PARAM_BLD_to_param(remote_params_bld);
	if (!remote_params) {
		slt_print(SLT_ERROR, "Error setting parameters\n");
		fails = 1;
		goto exit;
	}

	remote_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (!remote_ctx) {
		slt_print(SLT_ERROR, "Error creating remote ctx\n");
		fails = 1;
		goto exit;
	}

#ifdef PKEY
	if (EVP_PKEY_paramgen_init(remote_ctx) != 1) {
		slt_print(SLT_ERROR, "Error initializing remote ctx\n");
		fails = 1;
		goto exit;
	}

	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(remote_ctx, curve_NID) <= 0) {
		slt_print(SLT_ERROR, "Error setting ctx NID\n");
		fails = 1;
		goto exit;
	}

	if (!EVP_PKEY_paramgen(pctx, &params))
		goto err;
#endif

	if (EVP_PKEY_fromdata_init(remote_ctx) != 1) {
		slt_print(SLT_ERROR, "Error initializing remote ctx from data\n");
		fails = 1;
		goto exit;
	}

	if (EVP_PKEY_fromdata(remote_ctx, &remote_key,
			      EVP_PKEY_PUBLIC_KEY, remote_params) != 1) {
		slt_print(SLT_ERROR, "Error setting remote key\n");
		fails = 1;
		goto exit;
	}

	local_ctx = EVP_PKEY_CTX_new(local_key, NULL);
	if (!local_ctx) {
		slt_print(SLT_ERROR, "Error creating PKEY context\n");
		fails = 1;
		goto exit;
	}

	if (EVP_PKEY_derive_init(local_ctx) != 1) {
		slt_print(SLT_ERROR, "Error initializing PKEY context\n");
		fails = 1;
		goto exit;
	}

	if (EVP_PKEY_derive_set_peer(local_ctx, remote_key) != 1) {
		slt_print(SLT_ERROR, "Error setting peer key\n");
		fails = 1;
		goto exit;
	}

	ecdh_secret_len = sizeof(ecdh_secret);
	if (EVP_PKEY_derive(local_ctx, ecdh_secret, &ecdh_secret_len) != 1) {
		slt_print(SLT_ERROR, "Error deriving shared secret\n");
		fails = 1;
		goto exit;
	}
	if (ecdh_secret_len != 32) {
		slt_print(SLT_ERROR, "Unexpected ECDH secret len: %ld\n",
			  ecdh_secret_len);
		fails = 1;
		goto exit;
	}

	/* Perform KDF */
	kdf_input[0] = 0;
	kdf_input[1] = 0;
	kdf_input[2] = 0;
	kdf_input[3] = 1;
	memcpy(&kdf_input[4], ecdh_secret, 32);
	memcpy(&kdf_input[36], FixedInfo, 27);

	kdf_context = EVP_MD_CTX_new();
	if (!kdf_context) {
		slt_print(SLT_ERROR, "EVP context create fail\n");
		fails = 1;
		goto exit;
	}

	if (EVP_DigestInit_ex(kdf_context, EVP_sha256(), NULL) != 1) {
		slt_print(SLT_ERROR, "EVP context init fail\n");
		fails = 1;
		goto exit;
	}

	if (EVP_DigestUpdate(kdf_context, kdf_input, sizeof(kdf_input)) != 1) {
		slt_print(SLT_ERROR, "EVP digest update fail\n");
		fails = 1;
		goto exit;
	}

	key_size = sizeof(negotiated_kek);
	if (EVP_DigestFinal_ex(kdf_context, negotiated_kek, &key_size) != 1) {
		slt_print(SLT_ERROR, "EVP digest finalize fail\n");
		fails = 1;
		goto exit;
	}

	/* Inject new KEK with intermediate KEK */
	cipher_ctx = EVP_CIPHER_CTX_new();
	if (!cipher_ctx) {
		slt_print(SLT_ERROR, "EVP cipher create fail\n");
		fails = 1;
		goto exit;
	}

	if (EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(),
			       NULL, negotiated_kek, enc_kek) != 1) {
		slt_print(SLT_ERROR, "EVP encrypt init fail\n");
		fails = 1;
		goto exit;
	}
	enc_len = 32;
	if (EVP_EncryptUpdate(cipher_ctx, &enc_kek[12], &enc_len, kek_data, 32) != 1) {
		slt_print(SLT_ERROR, "EVP encrypt update fail\n");
		fails = 1;
		goto exit;
	}
	if (EVP_EncryptFinal_ex(cipher_ctx, &enc_kek[44], &enc_len) != 1) {
		slt_print(SLT_ERROR, "EVP encrypt finalize fail\n");
		fails = 1;
		goto exit;
	}
	if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG,
				16, &enc_kek[44]) != 1) {
		slt_print(SLT_ERROR, "EVP encrypt finalize fail\n");
		fails = 1;
		goto exit;
	}

	/* Use negotiated KEK to inject desired KEK */
	manage_args.key_identifier = malloc(sizeof(uint32_t));
	manage_args.kek_identifier = temp_kek_handle;
	manage_args.input_size = sizeof(enc_kek);
	manage_args.key_type = HSM_KEY_TYPE_AES_256;
	manage_args.key_group = key_group;
	manage_args.flags = 2; /* Create */;
	manage_args.key_info = 0x0A /* Transient KEK */;
	manage_args.input_data = enc_kek;

	err = hsm_manage_key(testCtx->hdl[index], &manage_args);
	if (err != HSM_NO_ERROR) {
		slt_print(SLT_ERROR, "Error injecting new KEK: 0x%x\n", err);
		fails = 1;
		goto exit;
	}
	testCtx->key_id[kek_id_number] = manage_args.key_identifier;
	testCtx->key_group[kek_id_number] = manage_args.key_group;
	slt_print(SLT_INFO, "new kek id 0x%x\n", *testCtx->key_id[kek_id_number]);

	/* Delete intermediate KEK*/
	manage_args.key_identifier = &temp_kek_handle;
	manage_args.kek_identifier = 0;
	manage_args.input_size = 0;
	manage_args.key_type = HSM_KEY_TYPE_AES_256;
	manage_args.key_group = key_group;
	manage_args.flags = 4; /* Delete */;
	manage_args.key_info = 0x0A /* Transient KEK */;
	manage_args.input_data = 0;

	err = hsm_manage_key(testCtx->hdl[index], &manage_args);
	if (err != HSM_NO_ERROR) {
		slt_print(SLT_ERROR, "Error deleting intermediate KEK: 0x%x\n", err);
		fails = 1;
		goto exit;
	}

exit:
	EVP_CIPHER_CTX_free(cipher_ctx);
	EVP_MD_CTX_free(kdf_context);
	EVP_PKEY_CTX_free(local_ctx);
	EVP_PKEY_CTX_free(remote_ctx);
	EVP_PKEY_free(local_key);
	EC_GROUP_free(local_group);
	EC_POINT_free(local_point);
	BN_clear_free(local_priv_bn);
	OSSL_PARAM_BLD_free(remote_params_bld);
	OSSL_PARAM_free(remote_params);
	FREE_BUFFER(kek_data);
	free(signed_message);
	return fails;
}

uint32_t tls_prf(const EVP_MD *hash_scheme, uint8_t *input_buff, uint32_t input_size,
		 char *label, uint8_t *seed_data, uint32_t seed_size,
		 uint8_t *output_buff, uint32_t output_size)
{
	uint8_t *seed;
	uint32_t label_size = strlen(label);
	uint32_t output_count = 0;
	uint32_t chunk_size;
	uint8_t *A_buff;
	uint8_t *hash_input_buff;
	uint8_t *hash_output_buff;
	uint32_t A_size;
	uint32_t hash_size;

	seed = malloc(input_size + seed_size);
	if (!seed)
		return 1;

	memcpy(seed, label, label_size);
	memcpy(&seed[label_size], seed_data, seed_size);

	if (hash_scheme == EVP_sha256())
		hash_size = 32;
	else
		hash_size = 48;

	A_buff = malloc(hash_size);
	hash_output_buff = malloc(hash_size);
	hash_input_buff = malloc(hash_size + label_size + seed_size);

	/* Create A(1) */
	if (!HMAC(hash_scheme, input_buff, input_size, seed,
		  label_size + seed_size, A_buff, &A_size)) {
		printf("HMAC error on first loop\n");
		free(A_buff);
		free(hash_input_buff);
		free(hash_output_buff);
		free(seed);
		return 1;
	}
	if (A_size != hash_size) {
		printf("Unexpected HMAC output size\n");
		free(A_buff);
		free(hash_input_buff);
		free(hash_output_buff);
		free(seed);
		return 1;
	}

	while (1) {
		/* Construct A(i) + seed for next input */
		memcpy(hash_input_buff, A_buff, hash_size);
		memcpy(&hash_input_buff[hash_size], seed, label_size + seed_size);

		if (!HMAC(hash_scheme, input_buff, input_size, hash_input_buff,
			  hash_size + label_size + seed_size, hash_output_buff, NULL)) {
			printf("HMAC error inside loop\n");
			free(A_buff);
			free(hash_input_buff);
			free(hash_output_buff);
			free(seed);
			return 1;
		}
		chunk_size = output_size - output_count;
		if (chunk_size > hash_size)
			chunk_size = hash_size;
		memcpy(&output_buff[output_count], hash_output_buff, chunk_size);
		output_count += chunk_size;

		if (output_count >= output_size)
			/* Done */
			break;

		/* Create next A(i) */
		memcpy(hash_input_buff, A_buff, hash_size);
		if (!HMAC(hash_scheme, input_buff, input_size,
			  hash_input_buff, hash_size, A_buff, NULL)) {
			printf("HMAC error inside loop\n");
			free(A_buff);
			free(hash_input_buff);
			free(hash_output_buff);
			free(seed);
			return 1;
		}
	}

	free(A_buff);
	free(hash_input_buff);
	free(hash_output_buff);
	free(seed);
	return 0;
}

#define TLS_KDF_INPUT_SIZE_NO_EMS 128
#define TLS_KDF_INPUT_SIZE_EMS_SHA256 0x60
#define TLS_KDF_INPUT_SIZE_EMS_SHA384 0x70
#define TLS_KDF_OUTPUT_SIZE 8
#define TLS_MASTER_SECRET_SIZE 48
#define MAX_KEY_BLOCK_SIZE 168

uint32_t test_hsm_full_key_exchange_tls(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	hsm_err_t err;
	hsm_err_t expected_return;

	uint32_t index;
	uint32_t number_of_generated_key_index;
	uint32_t *generated_key_id_number;
	uint32_t key_group;
	hsm_key_type_t initiator_public_data_type;
	hsm_key_exchange_scheme_id_t key_exchange_scheme;
	hsm_kdf_algo_id_t kdf_algorithm;
	uint8_t kdf_input_size;
	hsm_op_key_exchange_flags_t flags;

	uint8_t *output_buffer_index = NULL;
	uint32_t curr_buffer_index = 0;
	uint32_t ref_data_size;
	uint8_t *ref_data = NULL;

	uint8_t *kdf_input_data = NULL;
	uint8_t kdf_output_data[TLS_KDF_OUTPUT_SIZE];
	uint32_t seed_size;
	char *label_ptr;

	EVP_PKEY *local_key = NULL;
	uint8_t *local_pub_key = NULL;
	uint8_t remote_pub_key[97];
	size_t local_pub_key_len;
	uint32_t pub_key_size;
	char *ssl_curve;
	int curve_NID;

	op_key_exchange_args_t ke_args;

	const EVP_MD *hash_scheme;
	EVP_CIPHER_CTX *cipher_ctx = NULL;
	const EVP_CIPHER *cipher_scheme;
	EVP_PKEY_CTX *remote_ctx = NULL;
	EVP_PKEY_CTX *local_ctx = NULL;
	EVP_PKEY *remote_key = NULL;
	OSSL_PARAM_BLD *remote_params_bld = NULL;
	OSSL_PARAM *remote_params = NULL;

	uint8_t ecdh_secret[48];
	size_t ecdh_secret_len;
	uint8_t master_secret[TLS_MASTER_SECRET_SIZE];
	uint8_t key_block[MAX_KEY_BLOCK_SIZE];
	uint32_t mac_length;
	uint32_t key_length;

	uint8_t *hash_data = NULL;
	uint8_t *enc_data = NULL;
	uint32_t out_length;
	uint32_t data_index;
	int i;

	index                                   = READ_VALUE(fp, uint32_t);
	number_of_generated_key_index            = READ_VALUE(fp, uint32_t);
	ke_args.shared_key_identifier_array_size =
		sizeof(uint32_t) * number_of_generated_key_index;
	generated_key_id_number = malloc(ke_args.shared_key_identifier_array_size);
	for (i = 0; i < number_of_generated_key_index; i++)
		generated_key_id_number[i] = READ_VALUE(fp, uint32_t);

	key_group                  = READ_VALUE(fp, uint16_t);
	initiator_public_data_type = READ_VALUE(fp, uint8_t);
	key_exchange_scheme        = READ_VALUE(fp, uint8_t);
	kdf_algorithm              = READ_VALUE(fp, uint8_t);
	flags                      = READ_VALUE(fp, uint8_t);
	if (flags & HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS) {
		switch (kdf_algorithm) {
		case HSM_KDF_HMAC_SHA_256_TLS_0_16_4:
		case HSM_KDF_HMAC_SHA_256_TLS_0_32_4:
		case HSM_KDF_HMAC_SHA_256_TLS_32_16_4:
			kdf_input_size = TLS_KDF_INPUT_SIZE_EMS_SHA256;
			break;
		case HSM_KDF_HMAC_SHA_384_TLS_48_32_4:
		case HSM_KDF_HMAC_SHA_384_TLS_0_32_4:
			kdf_input_size = TLS_KDF_INPUT_SIZE_EMS_SHA384;
			break;
		default:
			kdf_input_size = 0; /* Error case */
		}
	} else {
		kdf_input_size = TLS_KDF_INPUT_SIZE_NO_EMS;
	}
	kdf_input_data = READ_INPUT_BUFFER(fp, kdf_input_size);
	output_buffer_index = malloc(number_of_generated_key_index);
	for (i = 0; i < number_of_generated_key_index - 1; i++)
		output_buffer_index[i] = READ_VALUE(fp, uint8_t);

	ref_data_size   = READ_VALUE(fp, uint32_t);
	ref_data        = READ_INPUT_BUFFER(fp, ref_data_size);
	expected_return = READ_VALUE(fp, hsm_err_t);

	switch (initiator_public_data_type) {
	case HSM_KEY_TYPE_ECDSA_NIST_P256:
		ssl_curve = "P-256";
		curve_NID = NID_X9_62_prime256v1;
		pub_key_size = 64;
		break;

	case HSM_KEY_TYPE_ECDSA_NIST_P384:
		ssl_curve = "P-384";
		curve_NID = NID_secp384r1;
		pub_key_size = 96;
		break;

	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256:
		ssl_curve = "brainpoolP256r1";
		curve_NID = NID_brainpoolP256r1;
		pub_key_size = 64;
		break;

	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384:
		ssl_curve = "brainpoolP384r1";
		curve_NID = NID_brainpoolP384r1;
		pub_key_size = 96;
		break;

	default:
		slt_print(SLT_ERROR, "Public data type not implemented: 0x%x\n",
			  initiator_public_data_type);
		fails = 1;
		goto exit;
	}

	switch (kdf_algorithm) {
	case HSM_KDF_HMAC_SHA_256_TLS_0_16_4:
		hash_scheme = EVP_sha256();
		mac_length = 0;
		key_length = 16;
		break;

	case HSM_KDF_HMAC_SHA_384_TLS_0_32_4:
		hash_scheme = EVP_sha384();
		mac_length = 0;
		key_length = 32;
		break;

	case HSM_KDF_HMAC_SHA_256_TLS_0_32_4:
		hash_scheme = EVP_sha256();
		mac_length = 0;
		key_length = 32;
		break;

	case HSM_KDF_HMAC_SHA_256_TLS_32_16_4:
		hash_scheme = EVP_sha256();
		mac_length = 32;
		key_length = 16;
		break;

	case HSM_KDF_HMAC_SHA_384_TLS_48_32_4:
		hash_scheme = EVP_sha384();
		mac_length = 48;
		key_length = 32;
		break;

	default:
		slt_print(SLT_ERROR, "KDF algorithm not implemented: 0x%x\n",
			  kdf_algorithm);
		break;
	}

	if (ref_data_size % key_length != 0) {
		slt_print(SLT_ERROR, "Error: Padding for encryption not handled\n");
		fails = 1;
		goto exit;
	}

	/* Generate local key pair */
	local_key = EVP_EC_gen(ssl_curve);
	if (!local_key) {
		slt_print(SLT_ERROR, "Error creating local key\n");
		fails = 1;
		goto exit;
	}

	local_pub_key_len = sizeof(local_pub_key);

	if (EVP_PKEY_get_raw_public_key(local_key, local_pub_key,
					&local_pub_key_len) != 1) {
		slt_print(SLT_ERROR, "Error getting local public key\n");
		fails = 1;
		goto exit;
	}
	if (local_pub_key_len != 65) {
		slt_print(SLT_ERROR, "Unexpected local pub key length: %ld\n",
			  local_pub_key_len);
		fails = 1;
		goto exit;
	}

	/* Perform key exchange in hsm */
	ke_args.key_identifier              = 0;
	ke_args.shared_key_identifier_array =
		malloc(ke_args.shared_key_identifier_array_size);

	ke_args.ke_input_size               = pub_key_size;
	ke_args.ke_input                    = &local_pub_key[1];

	ke_args.ke_output_size              = pub_key_size;
	ke_args.ke_output                   = &remote_pub_key[1];

	ke_args.kdf_input_size              = kdf_input_size;
	ke_args.kdf_input                   = kdf_input_data;

	ke_args.kdf_output_size             = TLS_KDF_OUTPUT_SIZE;
	ke_args.kdf_output                  = kdf_output_data;

	ke_args.shared_key_group            = key_group;
	ke_args.shared_key_info             = 0x02 /* Transient */;
	ke_args.shared_key_type             = 0; /* Unused */
	ke_args.initiator_public_data_type  = initiator_public_data_type;
	ke_args.key_exchange_scheme         = key_exchange_scheme;
	ke_args.kdf_algorithm               = kdf_algorithm;
	ke_args.flags                       = flags;
	ke_args.signed_message = NULL;
	ke_args.signed_msg_size = 0;

	err = hsm_key_exchange(testCtx->hdl[index], &ke_args);

	if (err != HSM_NO_ERROR) {
		if (err != expected_return) {
			slt_print(SLT_ERROR, "Error from hsm for key exchange: 0x%x\n",
				  err);
			fails = 1;
		}
		goto exit;
	}
	for (uint8_t i = 0; i < number_of_generated_key_index; i++) {
		testCtx->key_id[generated_key_id_number[i]] =
			(uint32_t *)(ke_args.shared_key_identifier_array + (i * 4));
		testCtx->key_group[generated_key_id_number[i]] =
			ke_args.shared_key_group;
	}

	remote_pub_key[0] = 0x04;

	remote_params_bld = OSSL_PARAM_BLD_new();
	if (!remote_params_bld) {
		slt_print(SLT_ERROR, "Error creating parameter structure\n");
		fails = 1;
		goto exit;
	}

	if (OSSL_PARAM_BLD_push_utf8_string(remote_params_bld,
					    "group", ssl_curve, 0) != 1) {
		slt_print(SLT_ERROR, "Error setting curve parameter\n");
		fails = 1;
		goto exit;
	}

	if (OSSL_PARAM_BLD_push_octet_string(remote_params_bld,
					     "pub", remote_pub_key,
					     sizeof(remote_pub_key)) != 1) {
		slt_print(SLT_ERROR, "Error setting curve parameter\n");
		fails = 1;
		goto exit;
	}

	remote_params = OSSL_PARAM_BLD_to_param(remote_params_bld);
	if (!remote_params) {
		slt_print(SLT_ERROR, "Error setting parameters\n");
		fails = 1;
		goto exit;
	}

	remote_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (!remote_ctx) {
		slt_print(SLT_ERROR, "Error creating remote ctx\n");
		fails = 1;
		goto exit;
	}

	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(remote_ctx, curve_NID) <= 0) {
		slt_print(SLT_ERROR, "Error setting ctx NID\n");
		fails = 1;
		goto exit;
	}

	if (EVP_PKEY_fromdata_init(remote_ctx) != 1) {
		slt_print(SLT_ERROR, "Error initializing remote ctx\n");
		fails = 1;
		goto exit;
	}

	if (EVP_PKEY_fromdata(remote_ctx, &remote_key,
			      EVP_PKEY_PUBLIC_KEY, remote_params) != 1) {
		slt_print(SLT_ERROR, "Error creating setting remote key\n");
		fails = 1;
		goto exit;
	}

	local_ctx = EVP_PKEY_CTX_new(local_key, NULL);
	if (!local_ctx) {
		slt_print(SLT_ERROR, "Error creating PKEY context\n");
		fails = 1;
		goto exit;
	}

	if (EVP_PKEY_derive_init(local_ctx) != 1) {
		slt_print(SLT_ERROR, "Error initializing PKEY context\n");
		fails = 1;
		goto exit;
	}

	if (EVP_PKEY_derive_set_peer(local_ctx, remote_key) != 1) {
		slt_print(SLT_ERROR, "Error setting peer key\n");
		fails = 1;
		goto exit;
	}

	ecdh_secret_len = sizeof(ecdh_secret);
	if (EVP_PKEY_derive(local_ctx, ecdh_secret, &ecdh_secret_len) != 1) {
		slt_print(SLT_ERROR, "Error deriving shared secret\n");
		fails = 1;
		goto exit;
	}
	if (ecdh_secret_len != 32) {
		slt_print(SLT_ERROR, "Unexpected ECDH secret len: %ld\n",
			  ecdh_secret_len);
		fails = 1;
		goto exit;
	}

	/* Calculate master secret */
	if (flags & HSM_OP_KEY_EXCHANGE_FLAGS_USE_TLS_EMS) {
		label_ptr = "extended master secret";
		if (hash_scheme == EVP_sha256())
			seed_size = 32;
		else
			seed_size = 48;
	} else {
		label_ptr = "master secret";
		seed_size = 64;
	}

	if (tls_prf(hash_scheme, ecdh_secret, pub_key_size / 2, label_ptr,
		    kdf_input_data, seed_size, master_secret, TLS_MASTER_SECRET_SIZE)) {
		slt_print(SLT_ERROR, "extended master secret calculation failed\n");
		fails = 1;
		goto exit;
	}

	/* Calculate key block - big enough for all cases */
	if (tls_prf(hash_scheme, master_secret, TLS_MASTER_SECRET_SIZE, "key expansion",
		    &kdf_input_data[seed_size], 64, key_block, MAX_KEY_BLOCK_SIZE)) {
		slt_print(SLT_ERROR, "master secret calculation failed\n");
		fails = 1;
		goto exit;
	}

	/* Verify IV output */
	if (memcmp(kdf_output_data, &key_block[(mac_length * 2) + (key_length * 2)],
		   TLS_KDF_OUTPUT_SIZE)) {
		slt_print(SLT_ERROR, "IV output mismatch\n");
		fails = 1;
		goto exit;
	}

	if (mac_length) {
		/* Perform MAC with first key */
		hash_data = malloc(mac_length);
		if (!HMAC(hash_scheme, key_block, mac_length, ref_data,
			  ref_data_size, hash_data, &out_length)) {
			printf("HMAC error\n");
			fails = 1;
			goto exit;
		}
		if (out_length != mac_length) {
			slt_print(SLT_ERROR, "HMAC unexpected output length: %d\n",
				  out_length);
			fails = 1;
			goto exit;
		}

		/* Store MAC output */
		testCtx->mac_size[output_buffer_index[curr_buffer_index]] = mac_length;
		testCtx->mac_ptr[output_buffer_index[curr_buffer_index]] = hash_data;
		hash_data = NULL;
		curr_buffer_index++;

		/* Perform MAC with second key */
		hash_data = malloc(mac_length);
		if (!HMAC(hash_scheme, &key_block[mac_length], mac_length, ref_data,
			  ref_data_size, hash_data, &out_length)) {
			printf("HMAC error\n");
			fails = 1;
			goto exit;
		}
		if (out_length != mac_length) {
			slt_print(SLT_ERROR, "HMAC unexpected output length: %d\n",
				  out_length);
			fails = 1;
			goto exit;
		}

		/* Store MAC output */
		testCtx->mac_size[output_buffer_index[curr_buffer_index]] = mac_length;
		testCtx->mac_ptr[output_buffer_index[curr_buffer_index]] = hash_data;
		hash_data = NULL;
		curr_buffer_index++;
	}

	if (key_length == 16)
		cipher_scheme = EVP_aes_128_ecb();
	else
		cipher_scheme = EVP_aes_256_ecb();

	cipher_ctx = EVP_CIPHER_CTX_new();
	if (!cipher_ctx) {
		slt_print(SLT_ERROR, "EVP cipher create fail\n");
		fails = 1;
		goto exit;
	}

	/* Encrypt ref data with first key */
	enc_data = malloc(ref_data_size);
	if (EVP_EncryptInit_ex(cipher_ctx, cipher_scheme,
			       NULL, &key_block[(mac_length * 2)], NULL) != 1) {
		slt_print(SLT_ERROR, "EVP encrypt init fail\n");
		fails = 1;
		goto exit;
	}

	data_index = 0;
	while (data_index < ref_data_size) {
		if (EVP_EncryptUpdate(cipher_ctx, &enc_data[data_index],
				      &out_length, &ref_data[data_index],
				      key_length) != 1) {
			slt_print(SLT_ERROR, "EVP encrypt update fail\n");
			fails = 1;
			goto exit;
		}
		if (out_length != key_length) {
			slt_print(SLT_ERROR, "EVP encrypt unexpected output len: %d\n",
				  out_length);
			fails = 1;
			goto exit;
		}
		data_index += key_length;
	}

	/* Store encrypted output */
	testCtx->cipher_size[output_buffer_index[curr_buffer_index]] = ref_data_size;
	testCtx->cipher_ptr[output_buffer_index[curr_buffer_index]] = enc_data;
	enc_data = NULL;
	curr_buffer_index++;

	/* Encrypt ref data with second key */
	enc_data = malloc(ref_data_size);
	if (EVP_EncryptInit_ex(cipher_ctx, cipher_scheme, NULL,
			       &key_block[(mac_length * 2) + key_length], NULL) != 1) {
		slt_print(SLT_ERROR, "EVP encrypt init fail\n");
		fails = 1;
		goto exit;
	}

	data_index = 0;
	while (data_index < ref_data_size) {
		if (EVP_EncryptUpdate(cipher_ctx,  &enc_data[data_index],
				      &out_length, &ref_data[data_index],
				      key_length) != 1) {
			slt_print(SLT_ERROR, "EVP encrypt update fail\n");
			fails = 1;
			goto exit;
		}
		if (out_length != key_length) {
			slt_print(SLT_ERROR,
				  "EVP encrypt unexpected output length: %d\n",
				  out_length);
			fails = 1;
			goto exit;
		}
		data_index += key_length;
	}

	/* Store encrypted output */
	testCtx->cipher_size[output_buffer_index[curr_buffer_index]] = ref_data_size;
	testCtx->cipher_ptr[output_buffer_index[curr_buffer_index]] = enc_data;
	enc_data = NULL;
	curr_buffer_index++;

exit:
	FREE_BUFFER(ref_data);
	FREE_BUFFER(hash_data);
	FREE_BUFFER(enc_data);
	EVP_CIPHER_CTX_free(cipher_ctx);
	OPENSSL_free(local_pub_key);
	EVP_PKEY_free(local_key);
	FREE_BUFFER(kdf_input_data);
	FREE_BUFFER(generated_key_id_number);
	FREE_BUFFER(output_buffer_index);
	return fails;
}
#else
uint32_t test_hsm_full_key_exchange_tls(hsm_test_struct_t *testCtx, FILE *fp)
{
	slt_print(SLT_ERROR, "Error: Need to compile with SSL support\n");
	return 1;
}

uint32_t test_hsm_full_key_exchange_sha_kek(hsm_test_struct_t *testCtx, FILE *fp)
{
	slt_print(SLT_ERROR, "Error: Need to compile with SSL support\n");
	return 1;
}
#endif

uint32_t test_hsm_tls_finish(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t index;
	uint32_t key_identifier;
	op_tls_finish_args_t args;

	index                          = READ_VALUE(fp, uint32_t);
	key_identifier                 = READ_VALUE(fp, uint32_t);

	args.handshake_hash_input_size = READ_VALUE(fp, uint16_t);
	args.handshake_hash_input      =
		READ_INPUT_BUFFER(fp, args.handshake_hash_input_size);

	args.verify_data_output_size   = READ_VALUE(fp, uint16_t);
	args.verify_data_output        =
		READ_OUTPUT_BUFFER(fp, args.verify_data_output_size);

	args.hash_algorithm            = READ_VALUE(fp, uint16_t);
	args.flags                     = READ_VALUE(fp, uint16_t);
	if (key_identifier == BAD_0) {
		args.key_identifier        = 0;
	} else if (key_identifier == BAD_VAL) {
		args.key_identifier         = BAD_VAL;
	} else if (!testCtx->key_id[key_identifier]) {
		args.key_identifier = BAD_VAL;
		slt_print(SLT_WARNING, "Saw invalid key id pointer\n");
	} else {
		args.key_identifier = *testCtx->key_id[key_identifier];
	}

	hsm_err_t err = hsm_tls_finish(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);

	READ_CHECK_BUFFER(testCtx, fp, args.verify_data_output,
			  args.verify_data_output_size);

	FREE_BUFFER(args.handshake_hash_input);
	FREE_BUFFER(args.verify_data_output);

	return fails;
}
