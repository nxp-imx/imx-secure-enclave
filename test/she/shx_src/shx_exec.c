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
};

int she_exec_function(int i, FILE *fp, void *testCtx)
{
	uint32_t these_fails = 0;

	these_fails += tests[i].func(testCtx, fp);

	return these_fails;
}
