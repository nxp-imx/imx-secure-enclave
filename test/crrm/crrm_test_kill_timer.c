// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crrm_utils.h"

hsm_err_t crrm_test_kill_timer(hsm_hdl_t crrm_hdl)
{
	op_get_nonce_args_t args = {0};
	op_refresh_AWDT_args_t targs = {0};
	signature_data *sdata = NULL;
	request_data *rdata = NULL;
	uint8_t info[NONCE_DATA_SIZE + TIMER_INFO_SIZE] = {0};
	uint8_t sign[SIGNATURE_LENGTH] = {0};
	size_t sig_len = 0;
	uint8_t timer_info_length = 0;
	hsm_err_t err;

	args.nonce_size = NONCE_DATA_SIZE + TIMER_INFO_SIZE;
	args.nonce_addr = info;
	err = crrm_get_nonce(crrm_hdl, &args);

	args.info = (nonce_info *)args.nonce_addr;
	if (err)
		return err;

	// populate refresh AWDT API data
	targs.timer_id = 0;
	targs.new_timer_value = 5000;
	targs.pub_key_index = 0;

	// populate signature data
	// args.output_size contains size of nonce data and timerinfo data
	// + 8 for timer_id, pub_key_index, new_timer_value;
	sdata = (signature_data *)malloc(args.output_size + 8);
	sdata->timer_id = targs.timer_id;
	sdata->pub_key_index = targs.pub_key_index;
	sdata->new_timer_value = targs.new_timer_value;
	memcpy(sdata->nonce_data, args.info->nonce_data, NONCE_DATA_SIZE);

	timer_info_length = args.output_size - NONCE_DATA_SIZE;

	memcpy(sdata->timer_info, args.info->timer_info, timer_info_length);

	const uint8_t *message = (const uint8_t *)sdata;

	if (!sign_message_raw_rs(message,
				 args.output_size + 8,
			 sign)) {
		printf("Signature generation failed\n");
		return HSM_GENERAL_ERROR;
	}

#ifdef DEBUG
		printf("Signature (R || S):\n");
		for (int i = 0; i < 64; i++) {
			printf("%02X", sign[i]);
			if ((i + 1) % 32 == 0)
				printf(" "); // Separate R and S
		}
#endif

	rdata = (request_data *)malloc(REQ_DATA_SIZE);
	rdata->new_timer_value = targs.new_timer_value;
	rdata->signature_length = SIGNATURE_LENGTH;
	memcpy(rdata->signature, sign, SIGNATURE_LENGTH);

	targs.req_data_addr = (uint8_t *)rdata;
	targs.req_data_size = REQ_DATA_SIZE;

	err = crrm_refresh_AWDT(crrm_hdl, &targs);

	return err;
}
