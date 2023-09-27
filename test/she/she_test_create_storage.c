// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdbool.h>
#include <stdio.h>

#include "she_api.h"
#include "sab_process_msg.h"
#include "sab_common_err.h"

she_err_t she_create_storage_test(she_hdl_t session_handle, she_hdl_t *key_store_hdl)
{
	open_svc_key_store_args_t key_store_args = {0};
	she_err_t err = SHE_GENERAL_ERROR;

	/* Get the access to the SHE keystore */
	key_store_args.key_store_identifier	= 0x0;
	key_store_args.authentication_nonce	= 0xbec00001;
#ifndef PSA_COMPLIANT
	key_store_args.max_updates_number	= 300;
#endif
	key_store_args.flags			= KEY_STORE_OPEN_FLAGS_CREATE |
						  KEY_STORE_OPEN_FLAGS_SHE |
						  KEY_STORE_OPEN_FLAGS_SET_MAC_LEN;

	key_store_args.min_mac_length		= 0x22;

	err = she_open_key_store_service(session_handle,
					 &key_store_args);
	if (err) {
		se_print("Key Store Open ret 0x%x ---> TEST FAILED\n", err);
		return err;
	}

	se_print("KEY store handle : 0x%x\n", key_store_args.key_store_hdl);

	*key_store_hdl = key_store_args.key_store_hdl;

	return err;
}

she_err_t do_she_create_storage_test(she_hdl_t session_handle,
				     she_hdl_t *key_store_hdl)
{
	she_err_t err;

	err = she_create_storage_test(session_handle, key_store_hdl);
	if (err)
		se_print("STORAGE CREATION TEST ---> FAILED\n");
	else
		se_print("STORAGE CREATION TEST ---> PASSED\n");

	return err;
}
