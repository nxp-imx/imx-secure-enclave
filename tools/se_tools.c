// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "test_common.h"
#include "hsm_api.h"
#include "test_importkey.h"

open_se_lib_serv_args_t se_lib_serv_args;
se_lib_hdl_t se_lib_serv_hdl;
#define SE_TOOL_SUPPRESS	"silent"

void hsm_test_sig_handler(int ht_signo, siginfo_t *ht_siginfo, void *ht_sigctx)
{
	se_lib_close_service(se_lib_serv_hdl);

	exit(EXIT_SUCCESS);
}

void se_tools_usage(void)
{
	printf("se_tools usage: se_tools [options]\n");
	printf("Options:\n");
	printf("-i or --info: show Global Info only.\n");
	printf("-d or --dev-info: show device info.\n");
	printf("-r or --get-rng: to generate RNG number.");
	printf("\n\t <input size>: Size in bytes.");
	printf("\n\t <filename> : %s, or", GEN_RNG_OUT_FILENAME);
	printf("\n\t \"%s\": %s", SE_TOOL_SUPPRESS, GEN_RNG_OUT_SILENT);
#ifdef PSA_COMPLIANT
	printf("\n-t or --dev-attest: attest the device & show device-attested info.\n");
	printf("-e or --get-event: show list of active events.\n");
	printf("-g or --gen-ele-key-blob: Generate blob for <\"%s\"/\"%s\">.",
	       GEN_ELE_KEY_BLOB_TYPE_DEK, GEN_ELE_KEY_BLOB_TYPE_OTFAD);
	printf("\n\t DEK: Mandatory input:");
	printf("\n\t\t<key-id>       : <0..UINT32_MAX>");
	printf("\n\t\t<algo>         : %s, %s",
	       GEN_ELE_KEY_BLOB_FORMAT_ALGO_AES_CBC,
	       GEN_ELE_KEY_BLOB_FORMAT_ALGO_SM4_CBC);
	printf("\n\t\t<key-type>     : %s, %s, %s, %s%s",
	       GEN_ELE_KEY_BLOB_FORMAT_ALGO_KEY_SZ_AES128,
	       GEN_ELE_KEY_BLOB_FORMAT_ALGO_KEY_SZ_AES192,
	       GEN_ELE_KEY_BLOB_FORMAT_ALGO_KEY_SZ_AES256,
	       GEN_ELE_KEY_BLOB_FORMAT_ALGO_KEY_SZ_SM4128,
	       GEN_ELE_KEY_BLOB_FORMAT_ALGO_SM4_EXCEPTION);
	printf("\n\t\t<Input-fname>  : %s", GEN_ELE_KEY_BLOB_DEK_KEY_FILE_NAME);
	printf("\n\t\t<Output-fname> : %s", GEN_ELE_KEY_BLOB_OUTPUT_DEK_BLOB_FILENAME);
	printf("\n\t OTFAD: Not Supported.\n");
	printf("-u or --lc-update <LC_STATE>: for life-cycle update only\n");
	printf("\t where, permitted values for LC_STATE are:");
	printf("\n\t\tHSM_NXP_PROVISIONED_STATE,");
	printf("\n\t\tHSM_OEM_OPEN_STATE,");
	printf("\n\t\tHSM_OEM_CLOSE_STATE,");
	printf("\n\t\tHSM_OEM_FIELD_RET_STATE,");
	printf("\n\t\tHSM_NXP_FIELD_RET_STATE,");
	printf("\n\t\tHSM_OEM_LOCKED_STATE\n");
	printf("-c or --commit: commit SRK revocation and FW version to fuses.");
	printf("\n\t <info_type>: Bitmask of information types to commit:");
	printf("\n\t\t0x01 - NXP SRK revocation");
	printf("\n\t\t0x02 - NXP FW version");
	printf("\n\t\t0x10 - OEM SRK revocation");
	printf("\n\t\t0x20 - OEM FW version");
	printf("\n\t\tExample: 0x03 commits both NXP SRK and FW version\n");
#endif
}

static int se_tool_fread(const uint8_t *in_fname, uint8_t *in_buf, uint16_t *in_buf_sz)
{
	FILE *se_fptr = fopen(in_fname, "rb");
	uint16_t in_buf_read = 0;
	size_t bytes_read_itr, in_file_sz;

	if (!se_fptr) {
		printf("Error: Failed to open file:%s\n", in_fname);
		return -errno;
	}

	if (fseek(se_fptr, 0, SEEK_END) != 0) {
		printf("Error: F-seek to end failed: %d\n", errno);
		fclose(se_fptr);
		return -errno;
	}

	in_file_sz = ftell(se_fptr);
	if (in_file_sz != *in_buf_sz) {
		printf("Error: Mismatch input-file-buf-sz[%zd bytes] & req-input-sz[%d",
		       in_file_sz, *in_buf_sz);
		printf(" bytes].\n");
		fclose(se_fptr);
		return -EINVAL;
	}

	if (fseek(se_fptr, 0, 0) != 0) {
		printf("Error: F-seek to start failed: %d\n", errno);
		fclose(se_fptr);
		return -errno;
	}

	do {
		bytes_read_itr = fread(in_buf + in_buf_read, 1, *in_buf_sz - in_buf_read,
				       se_fptr);
		in_buf_read += bytes_read_itr;
	} while (bytes_read_itr > 0);

	if (in_file_sz != in_buf_read)
		printf("Error: Mismatch F-seek-to-end-size[%zd] and read-size[%d]",
		       in_file_sz, in_buf_read);

#ifdef SE_TOOL_DEBUG
	hexdump((uint32_t *)in_buf, *in_buf_sz >> 2);
#endif
	fclose(se_fptr);

	return 0;
}

static int se_tool_fwrite(const uint8_t *out_fname, uint8_t *out_buf, int out_buf_sz)
{
	FILE *se_fptr = fopen(out_fname, "wb");
	uint16_t out_buf_write = 0;
	size_t bytes_write_itr;

	if (!se_fptr) {
		printf("Error: Failed to open file:%s\n", out_fname);
		return -errno;
	}
	do {
		bytes_write_itr = fwrite(out_buf + out_buf_write, 1,
					 out_buf_sz - out_buf_write,
					 se_fptr);
		out_buf_write += bytes_write_itr;
	} while (out_buf_write < out_buf_sz);

	fclose(se_fptr);

	return 0;
}

#ifdef PSA_COMPLIANT
static int get_lc_state(const char *ascii_state_str)
{
	if (!ascii_state_str)
		return 0;

	if (strcmp("HSM_NXP_PROVISIONED_STATE", ascii_state_str) == 0)
		return HSM_NXP_PROVISIONED_STATE;
	if (strcmp("HSM_OEM_OPEN_STATE", ascii_state_str) == 0)
		return HSM_OEM_OPEN_STATE;
	if (strcmp("HSM_OEM_CLOSE_STATE", ascii_state_str) == 0)
		return HSM_OEM_CLOSE_STATE;
	if (strcmp("HSM_OEM_FIELD_RET_STATE", ascii_state_str) == 0)
		return HSM_OEM_FIELD_RET_STATE;
	if (strcmp("HSM_NXP_FIELD_RET_STATE", ascii_state_str) == 0)
		return HSM_NXP_FIELD_RET_STATE;
	if (strcmp("HSM_OEM_LOCKED_STATE", ascii_state_str) == 0)
		return HSM_OEM_LOCKED_STATE;

	return 0;
}

int print_hsm_get_event(op_get_event_msg_args_t *hsm_get_event_args)
{
	int i;
	int err = 0;
	uint8_t rsp_code;
	hsm_event_report_info_t *hsm_event_report_list =
				hsm_get_event_args->hsm_event_report_list;

	for (i = 0; i < hsm_get_event_args->num_event_report; i++) {
		printf("\nEvent#%d:", i + 1);

		printf("\n\tCommand ID\t: 0x%02x",
		       hsm_event_report_list[i].event_cmd_id);

		printf("\n\tIPC ID\t\t: 0x%02x",
		       hsm_event_report_list[i].event_ipc_id);
		printf("  (0x01 = MU RTD, 0x02 = MU APPS)");

		printf("\n\tResponse Code");
		rsp_code = hsm_event_report_list[i].event_rsp_code >> 8;
		if ((hsm_event_report_list[i].event_rsp_code & 0xFF)
				== HSM_FATAL_FAILURE) {
			err++;
			printf("\t: FATAL Error code = 0x%02x", rsp_code);
		} else {
			if (hsm_event_report_list[i].event_rsp_code & 0xFF00)
				printf("\t: Warning code = 0x%02x", rsp_code);
		}
	}
	printf("\n\n");

	return err;
}
#endif

int process_option(int opt_arg_count, char **optarg)
{
	hsm_err_t err;

	if (opt_arg_count < 2) {
		se_tools_usage();
		return 0;
	}

	if ((strcmp("--help", optarg[1]) == 0 || strcmp("-h", optarg[1]) == 0)) {
		se_tools_usage();
		return 0;
	}

	if ((strcmp("--info", optarg[1]) == 0 || strcmp("-i", optarg[1]) == 0)) {
		print_global_info();
		return 0;
	}

	if ((strcmp("--dev-info", optarg[1]) == 0 || strcmp("-d", optarg[1]) == 0)) {
		dev_get_info(se_lib_serv_hdl);
		return 0;
	}

	if (((strcmp("--get-rng", optarg[1]) == 0 || strcmp("-r", optarg[1]) == 0))) {
		const uint8_t *output_fname = (opt_arg_count > 3) ? optarg[3] : NULL;
		bool flag_print_disabled = output_fname ? true : false;
		op_get_random_args_t rng_get_random_args = {0};
		uint8_t *rng_out_buff;

		if (opt_arg_count < 3) {
			se_tools_usage();
			return 0;
		}

		rng_get_random_args.random_size = atoi(optarg[2]);
		if (!rng_get_random_args.random_size)
			return 0;

		rng_out_buff = malloc(rng_get_random_args.random_size);
		if (!rng_out_buff) {
			printf("Error: Buffer alloc failed.\n");
			printf("Command failed.\n");
			return 0;
		}
		if (gen_rng_hex_str(se_lib_serv_hdl, &rng_get_random_args,
				    rng_out_buff, flag_print_disabled))
			goto rng_exit;

		if (!output_fname)
			goto rng_exit;

		if (!memcmp(output_fname, SE_TOOL_SUPPRESS, strlen(SE_TOOL_SUPPRESS)))
			goto rng_exit;

		if (se_tool_fwrite(output_fname, rng_out_buff,
				   rng_get_random_args.random_size))
			goto rng_exit;
rng_exit:
		free(rng_out_buff);
		return 0;
	}

#ifdef PSA_COMPLIANT
	if ((strcmp("--dev-attest", optarg[1]) == 0 || strcmp("-t", optarg[1]) == 0)) {
		perform_dev_attestation(se_lib_serv_hdl);
		dev_get_info(se_lib_serv_hdl);
		return 0;
	}

	if ((strcmp("--get-event", optarg[1]) == 0 || strcmp("-e", optarg[1]) == 0)) {
		op_get_event_msg_args_t hsm_get_event_args;

		err = hsm_get_event(se_lib_serv_hdl, &hsm_get_event_args);
		if (err != HSM_NO_ERROR) {
			printf("hsm_get_event failed err:0x%x\n", err);
			return 0;
		}
		printf("Checking for HSM events...\n\n");
		err = print_hsm_get_event(&hsm_get_event_args);
		return 0;
	}

	if ((strcmp("--lc-update", optarg[1]) == 0 || strcmp("-u", optarg[1]) == 0)) {
		op_get_event_msg_args_t hsm_get_event_args;

		err = hsm_get_event(se_lib_serv_hdl, &hsm_get_event_args);
		if (err != HSM_NO_ERROR)
			printf("hsm_get_event failed err:0x%x\n", err);

		printf("Checking for HSM events before doing LC-update.\n\n");
		err = print_hsm_get_event(&hsm_get_event_args);
		if (hsm_get_event_args.num_event_report && err) {
			printf("Due HSM events, Life Cycle update is not done.\n");
			return 0;
		}
		if (opt_arg_count == 3)
			lc_update_info(se_lib_serv_hdl, get_lc_state(optarg[2]));
		else
			se_tools_usage();

		return 0;
	}

	if ((strcmp("--gen-ele-key-blob", optarg[1]) == 0 ||
	     strcmp("-g", optarg[1]) == 0)) {
		const uint8_t *payload_fname = (opt_arg_count >= 8) ? optarg[6] : NULL;
		const uint8_t *output_fname = (opt_arg_count >= 8) ? optarg[7] : NULL;
		uint8_t payload[OP_GEN_ELE_KEY_BLOB_PAYLOAD_MAX_SZ];
		hsm_op_gen_ele_key_blob_flags_t flag;
		hsm_op_gen_ele_key_blob_algo_t algo;
		uint8_t generated_ele_dek_blob[GEN_ELE_KEY_BLOB_OVERHEAD_SZ +
						OP_GEN_ELE_KEY_BLOB_PAYLOAD_MAX_SZ];
		uint8_t gen_ele_dek_blob_sz = GEN_ELE_KEY_BLOB_OVERHEAD_SZ +
						OP_GEN_ELE_KEY_BLOB_PAYLOAD_MAX_SZ;
		uint16_t key_size;
		uint32_t key_id;

		if (opt_arg_count != 8) {
			se_tools_usage();
			return 0;
		}

		if (!memcmp(optarg[2], GEN_ELE_KEY_BLOB_TYPE_DEK, strlen(optarg[2]))) {
			flag = HSM_OP_GEN_ELE_KEY_BLOB_FLAG_BLOB_TYPE_DEK;
		} else if (!memcmp(optarg[2], GEN_ELE_KEY_BLOB_TYPE_OTFAD,
			   strlen(optarg[2]))) {
			flag = HSM_OP_GEN_ELE_KEY_BLOB_FLAG_BLOB_TYPE_OTFAD_CONF;
		} else {
			se_tools_usage();
			return 0;
		}

		algo = gen_ele_key_blob_get_algo(flag, optarg[4]);
		if (!algo) {
			se_tools_usage();
			return 0;
		}
		key_size = gen_ele_key_blob_get_keysize(flag, optarg[5]);
		if (!key_size) {
			se_tools_usage();
			return 0;
		}
		key_id = atoi(optarg[3]);
		if (!payload_fname) {
			printf("Error: Empty Out-file name.\n");
			return 0;
		}
		memset(payload, 0, sizeof(payload));
		if (se_tool_fread(payload_fname, payload, &key_size))
			return 0;

		err = test_gen_ele_key_blob(se_lib_serv_hdl, flag, key_id,
					    algo, payload, key_size,
					    generated_ele_dek_blob,
					    &gen_ele_dek_blob_sz);
		if (err)
			printf("Failed to generate ELE Key blob for DEK.\n");

		if (!output_fname) {
			printf("Error: Empty Out-file name.\n");
			return 0;
		}

		if (se_tool_fwrite(output_fname, generated_ele_dek_blob,
				   gen_ele_dek_blob_sz))
			return 0;

#ifdef SE_TOOL_DEBUG
		key_size = gen_ele_dek_blob_sz;
		se_tool_fread(output_fname, generated_ele_dek_blob, &key_size);
#endif
		return 0;
	}

	if ((strcmp("--commit", optarg[1]) == 0 || strcmp("-c", optarg[1]) == 0)) {
		uint32_t info_type;

		if (opt_arg_count < 3) {
			printf("Error: Missing info_type parameter\n");
			se_tools_usage();
			return 0;
		}

		/* Parse info_type (supports hex with 0x prefix or decimal) */
		if (strncmp(optarg[2], "0x", 2) == 0 ||
		    strncmp(optarg[2], "0X", 2) == 0)
			info_type = (uint32_t)strtoul(optarg[2], NULL, 16);
		else
			info_type = (uint32_t)strtoul(optarg[2], NULL, 10);

		if (info_type == 0) {
			printf("Error: Invalid info_type value\n");
			se_tools_usage();
			return 0;
		}

		/* Validate info_type bitmask */
		uint32_t valid_bits = HSM_COMMIT_NXP_SRK_REVOCATION |
				      HSM_COMMIT_NXP_FW_VERSION |
				      HSM_COMMIT_OEM_SRK_REVOCATION |
				      HSM_COMMIT_OEM_FW_VERSION;

		if (info_type & ~valid_bits) {
			printf("Error: Invalid bits in info_type (0x%08X)\n", info_type);
			printf("Valid bits: 0x%08X\n", valid_bits);
			se_tools_usage();
			return 0;
		}

		exchange_commit_command(se_lib_serv_hdl, info_type);
		return 0;
	}
#endif
}

int main(int argc, char *argv[])
{
	struct sigaction hsm_test_sigact = {0};
	hsm_err_t err;

	sigemptyset(&hsm_test_sigact.sa_mask);
	hsm_test_sigact.sa_flags = SA_SIGINFO;
	hsm_test_sigact.sa_sigaction = hsm_test_sig_handler;

	/* Register hsm test signal handler for SIGINT (CTRL+C) signal. */
	if (sigaction(SIGINT, &hsm_test_sigact, NULL)) {
		perror("failed to register hsm_test_sig_handler\n");
		return 0;
	}

	se_lib_serv_args.mu_type = HSM1;
	err = se_lib_open_service(&se_lib_serv_args, &se_lib_serv_hdl);
	if (err != HSM_NO_ERROR) {
		printf("SE lib open service failed err:0x%x\n", err);
		return 0;
	}

	process_option(argc, argv);

	if (se_lib_serv_args.se_lib_serv_hdl)  {
		se_lib_close_service(se_lib_serv_args.se_lib_serv_hdl);
		se_lib_serv_args.se_lib_serv_hdl = 0;
	}

	return 0;
}
