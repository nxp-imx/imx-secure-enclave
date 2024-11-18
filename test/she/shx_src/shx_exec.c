// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "shx_test.h"
#include "shx_exec.h"
#include "shx_test_sessions.h"
#include "shx_test_key_store.h"
#include "shx_test_utils.h"
#include "shx_test_cipher.h"
#include "shx_test_keys.h"
#include "shx_test_plain_keys.h"
#include "shx_test_mac.h"
#include "shx_test_mac_mubuff_v2.h"
#include "shx_test_cbc.h"
#include "shx_test_ecb.h"
#include "shx_test_rng.h"
#include "shx_test_status.h"
#include "shx_test_cmac.h"

/*
 * As known limitation, a test name can't be included in another test name
 * e.g. if a test named SHE_TEST_LOAD_KEY exists,
 * it can't exist SHE_TEST_LOAD_KEY_EXT
 */
struct she_test_entry_t tests[SHE_TEST_COUNT] = {
	{"SHE_TEST_CLOSE_SESSION", she_test_close_session},
	{"SHE_TEST_OPEN_SESSION", she_test_open_session},
	{"SHE_TEST_KEY_STORE_OPEN", she_test_key_store_open},
	{"SHE_TEST_KEY_STORE_CLOSE", she_test_key_store_close},
	{"SHE_TEST_UTILS_OPEN", she_test_utils_open},
	{"SHE_TEST_UTILS_CLOSE", she_test_utils_close},
	{"SHE_TEST_CIPHER_OPEN", she_test_cipher_open},
	{"SHE_TEST_CIPHER_CLOSE", she_test_cipher_close},
	{"SHE_TEST_LOAD_KEY", she_test_load_key},
	{"SHE_TEST_EXT_LOAD_KEY", she_test_load_key_ext},
	{"SHE_TEST_LOAD_PLAIN_KEY", she_test_load_plain_key},
	{"SHE_TEST_EXPORT_RAM_KEY", she_test_export_plain_key},
	{"SHE_TEST_MAC_GEN", she_test_mac_gen},
	{"SHE_TEST_MAC_VERIF", she_test_mac_verif},
	{"EXT_SHE_TEST_MAC_VERIF_BIT", she_test_mac_verif_bit_ext},
	{"SHE_TEST_MAC_MUBUFF_V2_GEN", she_test_mac_mubuff_v2_gen},
	{"SHE_TEST_MAC_MUBUFF_V2_VERIF", she_test_mac_mubuff_v2_verif},
	{"EXT_SHE_TEST_MAC_MUBUFF_V2_VERIF_BIT", she_test_mac_mubuff_v2_verif_bit_ext},
	{"SHE_TEST_CBC_ENC", she_test_cbc_enc},
	{"SHE_TEST_CBC_DEC", she_test_cbc_dec},
	{"SHE_TEST_ECB_ENC", she_test_ecb_enc},
	{"SHE_TEST_ECB_DEC", she_test_ecb_dec},
	{"SHE_TEST_RNG_INIT", she_test_rng_init},
	{"SHE_TEST_EXTEND_SEED", she_test_extend_seed},
	{"SHE_TEST_RND", she_test_rnd},
	{"SHE_TEST_RNG_CLOSE", she_test_rng_close},
	{"SHE_TEST_GET_STATUS", she_test_get_status},
	{"SHE_TEST_GET_ID", she_test_get_id},
	{"SHE_TEST_GET_LAST_RATING_CODE", she_test_get_last_rating_code},
	{"SHE_TEST_GET_INFO", she_test_get_info},
	{"SHE_TEST_CMAC_GEN", she_test_cmac_gen},
	{"SHE_TEST_CMAC_VERIF", she_test_cmac_verif},
	{"SHE_TEST_OPEN_CMAC_SESSION", she_test_open_cmac_session},
	{"SHE_TEST_CLOSE_CMAC_SESSION", she_test_close_cmac_session}
};

int she_exec_function(int i, FILE *fp, void *testCtx)
{
	uint32_t these_fails = 0;

	these_fails += tests[i].func(testCtx, fp);

	return these_fails;
}
