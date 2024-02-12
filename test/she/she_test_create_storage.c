// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <stdbool.h>
#include <stdio.h>

#include "she_api.h"
#include "sab_process_msg.h"
#include "sab_common_err.h"

she_err_t she_create_storage_test(she_hdl_t session_handle,
				  open_svc_key_store_args_t *args)
{
	she_err_t err = SHE_GENERAL_ERROR;

	err = she_open_key_store_service(session_handle,
					 args);
	if (err) {
		se_print("Key Store Open (CREATE) ret 0x%x.\n", err);

		if (err != SHE_KEY_STORE_CONFLICT && err != SHE_ID_CONFLICT) {
			se_print("Key Store Open (CREATE) ret 0x%x ---> TEST FAILED\n",
				 err);
			return err;
		}

		args->flags &= ~(KEY_STORE_OPEN_FLAGS_CREATE |
				KEY_STORE_OPEN_FLAGS_STRICT_OPERATION |
				KEY_STORE_OPEN_FLAGS_SET_MAC_LEN);

		err = she_open_key_store_service(session_handle,
						 args);
		if (err != SHE_NO_ERROR) {
			se_print("Key Store Open (LOAD) ret 0x%x ---> TEST FAILED\n",
				 err);
			return err;
		}
	}

	return err;
}

she_err_t do_she_create_storage_test(she_hdl_t session_handle,
				     open_svc_key_store_args_t *args)
{
	she_err_t err;

	err = she_create_storage_test(session_handle, args);
	if (err)
		se_print("STORAGE CREATION TEST ---> FAILED\n");
	else
		se_print("STORAGE CREATION TEST ---> PASSED\n");

	return err;
}
