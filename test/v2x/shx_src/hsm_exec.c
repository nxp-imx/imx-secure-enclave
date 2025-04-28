// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <time.h>
#include <sys/types.h>

#include "hsm_exec.h"

#include "test_hsm_session.h"
#include "test_hsm_key_store_service.h"
#include "test_hsm_key_management_service.h"
#include "test_hsm_generate_key.h"
#include "test_hsm_manage_key.h"
#include "test_hsm_butterfly_key_expansion.h"
#include "test_hsm_cipher_service.h"
#include "test_hsm_cipher_one_go.h"
#include "test_hsm_ecies_decryption.h"
#include "test_hsm_signature_generation_service.h"
#include "test_hsm_generate_signature.h"
#include "test_hsm_prepare_signature.h"
#include "test_hsm_signature_verification_service.h"
#include "test_hsm_verify_signature.h"
#include "test_hsm_import_public_key.h"
#include "test_hsm_rng_service.h"
#include "test_hsm_get_random.h"
#include "test_hsm_hash_service.h"
#include "test_hsm_hash_one_go.h"
#include "test_hsm_hash_one_go_mct.h"
#include "test_hsm_pub_key_reconstruction.h"
#include "test_hsm_pub_key_decompression.h"
#include "test_hsm_ecies_encryption.h"
#include "test_hsm_storage_manager.h"
#include "test_hsm_pub_key_recovery.h"
#include "test_hsm_manage_key_group.h"
#include "test_hsm_data_storage_service.h"
#include "test_hsm_data_storage.h"
#include "test_hsm_auth_enc.h"
#include "test_hsm_kek_export.h"
#include "test_hsm_get_info.h"
#include "test_hsm_mac_service.h"
#include "test_hsm_mac_one_go.h"
#include "test_hsm_sm2_get_z.h"
#include "test_hsm_cavp_cipher_one_go_ecb_mct.h"
#include "test_hsm_cavp_cipher_one_go_cbc_mct.h"
#include "test_hsm_cavp_support.h"
#include "test_hsm_key_exchange.h"
#include "test_hsm_get_entropy.h"
#include "test_hsm_run_fips_selftests.h"

/*
 * As known limitation, a test name can't be included in another test name
 * e.g. if a test named SHE_TEST_LOAD_KEY exists,
 * it can't exist SHE_TEST_LOAD_KEY_EXT
 */
struct test_entry_t tests[HSM_TEST_COUNT] = {
	{ "HSM_OPEN_SESSION", test_hsm_open_session },
	{ "HSM_CLOSE_SESSION", test_hsm_close_session },
	{ "HSM_OPEN_KEY_STORE_SERVICE", test_hsm_open_key_store_service },
	{ "HSM_CLOSE_KEY_STORE_SERVICE", test_hsm_close_key_store_service },
	{ "HSM_OPEN_KEY_MANAGEMENT_SERVICE", test_hsm_open_key_management_service },
	{ "HSM_CLOSE_KEY_MANAGEMENT_SERVICE", test_hsm_close_key_management_service },
	{ "HSM_GENERATE_N_KEY", test_hsm_generate_n_key},
	{ "HSM_GENERATE_KEY", test_hsm_generate_key },
	{ "HSM_GENERATE_N_GROUPS", test_hsm_generate_n_groups},
	{ "HSM_BULK_GENERATE_KEY", test_hsm_bulk_generate_key},
	{ "HSM_MANAGE_KEY", test_hsm_manage_key },
	{ "HSM_BULK_MANAGE_KEY", test_hsm_bulk_manage_key },
	{ "HSM_BUTTERFLY_KEY_EXPANSION", test_hsm_butterfly_key_expansion },
	{ "HSM_OPEN_CIPHER_SERVICE", test_hsm_open_cipher_service },
	{ "HSM_CLOSE_CIPHER_SERVICE", test_hsm_close_cipher_service },
	{ "HSM_CIPHER_ONE_GO", test_hsm_cipher_one_go },
	{ "HSM_ECIES_DECRYPTION", test_hsm_ecies_decryption },
	{ "HSM_ECIES_ENCRYPTION", test_hsm_ecies_encryption },
	{ "HSM_OPEN_SIGNATURE_GENERATION_SERVICE",
	  test_hsm_open_signature_generation_service },
	{ "HSM_CLOSE_SIGNATURE_GENERATION_SERVICE",
	  test_hsm_close_signature_generation_service },
	{ "HSM_GENERATE_SIGNATURE", test_hsm_generate_signature },
	{ "HSM_PREPARE_SIGNATURE", test_hsm_prepare_signature },
	{ "HSM_OPEN_SIGNATURE_VERIFICATION_SERVICE",
	  test_hsm_open_signature_verification_service },
	{ "HSM_CLOSE_SIGNATURE_VERIFICATION_SERVICE",
	  test_hsm_close_signature_verification_service },
	{ "HSM_VERIFY_SIGNATURE", test_hsm_verify_signature },
	{ "HSM_IMPORT_PUBLIC_KEY", test_hsm_import_public_key },
	{ "HSM_PUB_KEY_RECONSTRUCTION", test_hsm_pub_key_reconstruction },
	{ "HSM_PUB_KEY_DECOMPRESSION", test_hsm_pub_key_decompression },
	{ "HSM_OPEN_RNG_SERVICE", test_hsm_open_rng_service },
	{ "HSM_CLOSE_RNG_SERVICE", test_hsm_close_rng_service },
	{ "HSM_GET_RANDOM", test_hsm_get_random },
	{ "HSM_GET_N_RANDOM", test_hsm_get_n_random },
	{ "HSM_OPEN_HASH_SERVICE", test_hsm_open_hash_service },
	{ "HSM_CLOSE_HASH_SERVICE", test_hsm_close_hash_service },
	{ "HSM_HASH_ONE_GO", test_hsm_hash_one_go },
	{ "HSM_TEST_START_STORAGE_MANAGER", test_hsm_start_storage_manager},
	{ "HSM_TEST_STOP_STORAGE_MANAGER", test_hsm_stop_storage_manager},
	{ "HSM_PUB_KEY_RECOVERY", test_hsm_pub_key_recovery},
	{ "HSM_MANAGE_GROUP", test_hsm_manage_key_group},
	{ "LOAD_KEY_FILE", load_key },
	{ "SET_SAVE_KEY_FILE", save_key },
	{ "HSM_OPEN_DATA_STORAGE_SERVICE", test_hsm_open_data_storage_service },
	{ "HSM_CLOSE_DATA_STORAGE_SERVICE", test_hsm_close_data_storage_service },
	{ "HSM_DATA_STORAGE", test_hsm_data_storage },
	{ "HSM_AUTH_ENC", test_hsm_auth_enc },
	{ "HSM_ROOT_KEK_EXPORT", test_hsm_root_kek_export },
	{ "HSM_GET_INFO", test_hsm_get_info},
	{ "HSM_OPEN_MAC_SERVICE", test_hsm_open_mac_service },
	{ "HSM_CLOSE_MAC_SERVICE", test_hsm_close_mac_service },
	{ "HSM_MAC_ONE_GO", test_hsm_mac_one_go },
	{ "HSM_CAVP_HASH_ONE_GO_MCT", test_hsm_hash_one_go_mct },
	{ "HSM_CAVP_CIPHER_ONE_GO_ECB_MCT", test_hsm_cavp_cipher_one_go_ecb_mct },
	{ "HSM_CAVP_CIPHER_ONE_GO_CBC_MCT", test_hsm_cavp_cipher_one_go_cbc_mct },
	{ "HSM_CAVP_SUPPORT", test_hsm_cavp_support },
	{ "HSM_MCT_CAVP_SUPPORT", test_hsm_cavp_support_mct },
	{ "HSM_SM2_GET_Z", test_hsm_sm2_get_z},
	{ "HSM_KEY_EXCHANGE", test_hsm_key_exchange },
	{ "HSM_TEST_START_V2X_STORAGE_MANAGER", test_hsm_start_v2x_storage_manager },
	{ "HSM_TEST_STOP_V2X_STORAGE_MANAGER", test_hsm_stop_v2x_storage_manager },
	{ "HSM_FULL_KEY_EXCHANGE_SHA_KEK", test_hsm_full_key_exchange_sha_kek},
	{ "HSM_GET_ENTROPY", test_hsm_get_entropy },
	{ "HSM_OPEN_ENTROPY_FILE", test_hsm_open_entropy_file },
	{ "HSM_CLOSE_ENTROPY_FILE", test_hsm_close_entropy_file },
	{ "HSM_SWEEP_NOISE_COUNTER", test_hsm_sweep_noise_counter },
	{ "HSM_SWEEP_ERROR_COUNTER", test_hsm_sweep_error_counter },
	{ "HSM_FULL_KEY_EXCHANGE_TLS", test_hsm_full_key_exchange_tls },
	{ "HSM_TLS_FINISH", test_hsm_tls_finish },
	{ "HSM_VERIFY_AUTH_ENCRYPTION", test_hsm_verify_auth_encryption },
	{ "HSM_EXT_GENERATE_KEY", test_hsm_generate_key_ext },
	{ "HSM_EXT_MANAGE_KEY", test_hsm_manage_key_ext },
	{ "HSM_VERIFY_CIPHER_ONE_GO_CCM_ENCRYPTION",
	  test_hsm_verify_cipher_one_go_ccm_encryption },
	{ "HSM_GET_TRNG_FREQ", test_hsm_get_trng_freq },
	{ "HSM_SWEEP_ERROR_VARIANCE", test_hsm_sweep_error_variance },
	{ "HSM_FIPS_SELFTEST", test_hsm_run_fips_selftests },
	{ "HSM_SM2_ECES_OPEN", test_hsm_sm2_eces_open },
	{ "HSM_SM2_ECES_ENC", test_hsm_sm2_eces_enc },
	{ "HSM_STANDALONE_BUTTERFLY_KEY_EXPANSION",
	  test_hsm_standalone_butterfly_key_expansion },
	{ "HSM_OPEN_GENERIC_CRYPTO_SERVICE", test_hsm_open_generic_crypto_service },
};

struct hsm_arg_struct {
	int i;
	FILE *fp;
	hsm_test_struct_t *testCtx;
	int *ret_val;
};

uint32_t save_key(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t result = 0;
	uint32_t fails = 0;
	char *filename = NULL;
	size_t len = 0;

	if (getline(&filename, &len, fp) != -1) {
		while (strlen(filename) && filename[strlen(filename) - 1] < ' ')
			filename[strlen(filename) - 1] = '\0';
		testCtx->fp = fopen(filename, "wb"); // will clean the file if it exists
		if (!testCtx->fp) {
			slt_print(SLT_ERROR,
				  "key id file '%s' can't be opened in W mode", filename);
			result = 1;
		}
	}

	CHECK_VALUE(testCtx, result, 0);

	FREE_BUFFER(filename);

	return fails;
}

uint32_t load_key(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint16_t ik;
	uint32_t ret = 0;
	char *filename = NULL;
	size_t len = 0;

	if (getline(&filename, &len, fp) != -1) {
		while (strlen(filename) && filename[strlen(filename) - 1] < ' ')
			filename[strlen(filename) - 1] = '\0';
		testCtx->fp = fopen(filename, "rb");
		if (!testCtx->fp) {
			slt_print(SLT_ERROR, "key id file '%s' does not exist", filename);
			ret = 1;
		} else {
			ik = 0;
			test_keyid_t *data = malloc(20 * sizeof(test_keyid_t));
			/* malloc could fail */
			if (!data) {
				slt_print(SLT_ERROR, "Malloc: out of mem error\n");
				fclose(testCtx->fp);
				goto out;
			}

			testCtx->data = data;
			while (true) {
				ret = fread(&data[ik], 1, sizeof(test_keyid_t),
					    testCtx->fp);
				if (ret != sizeof(test_keyid_t)) {
					slt_print(SLT_ERROR,
						  "Error: read %d bytes from file '%s'\n",
						  ret, filename);
					break;
				}
				slt_print(SLT_INFO, "idx %d, key id %x, key group %d\n",
					  ik + 1, data[ik].key_id, data[ik].key_group);
				testCtx->key_id[ik + 1] = &data[ik].key_id;
				testCtx->key_group[ik + 1] = data[ik].key_group;
				if (feof(testCtx->fp))
					break;
				ik++;
				if (ik >= 20) {
					/* If not EOF and still having keys */
					slt_print(SLT_ERROR,
						  "Too many keys, Max allowed is 20!\n");
					break;
				}
			}
			fclose(testCtx->fp);
		}
	}

out:
	FREE_BUFFER(filename);

	testCtx->fp = NULL;

	return !!ret;
}

int hsm_exec_function(int i, FILE *fp, void *testCtx)
{
	uint32_t these_fails = 0;

	these_fails += tests[i].func(testCtx, fp);

	return these_fails;
}
