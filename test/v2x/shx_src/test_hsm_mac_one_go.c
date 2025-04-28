// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_mac_one_go.h"

#define DUMMY_BUF_SIZE      16

uint32_t test_hsm_mac_one_go(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;
	uint32_t key_id_number;
	uint32_t mac_store_index;
	op_mac_one_go_args_t args;
	uint8_t mac_size_bytes;
	uint8_t dummy_buf[DUMMY_BUF_SIZE];

	// read the mac index.
	index                    = READ_VALUE(fp, uint32_t);
	key_id_number            = READ_VALUE(fp, uint32_t);
	if (key_id_number == BAD_VAL) {
		args.key_identifier = BAD_VAL;
	} else if (key_id_number == BAD_0) {
		args.key_identifier = 0;
	} else if (!testCtx->key_id[key_id_number]) {
		args.key_identifier = BAD_VAL;
		slt_print(SLT_WARNING, "Saw invalid key id pointer\n");
	} else {
		/* key gen cmd to be executed before */
		args.key_identifier = *testCtx->key_id[key_id_number];
	}

	mac_store_index          = READ_VALUE(fp, uint32_t);
	args.algorithm           = READ_VALUE(fp, hsm_op_mac_one_go_algo_t);
	args.flags               = READ_VALUE(fp, hsm_op_mac_one_go_flags_t);
	args.payload_size        = READ_VALUE(fp, uint16_t);
	slt_print(SLT_DEBUG, "VALUES OF payload size %d\n", args.payload_size);
	if (args.payload_size != BAD_0 && args.payload_size != BAD_1)
		args.payload = READ_INPUT_BUFFER(fp, args.payload_size);
	else
		args.payload = READ_INPUT_BUFFER(fp, 0);

	if (args.payload_size == 0) {
		/* Test null payload size */
		args.payload = dummy_buf;
	} else if (args.payload_size == BAD_0) {
		/* Test null payload */
		args.payload_size = DUMMY_BUF_SIZE;
		args.payload = NULL;
	} else if (args.payload_size == BAD_1) {
		/* Test bad payload pointer */
		args.payload_size = DUMMY_BUF_SIZE;
		args.payload = (uint8_t *)BAD_VAL;
	} else {
		/* No special handling required for input buffer */
	}

	/* Get input and input size
	 * But for DECRYPT case we replace it by:
	 * - Addr = 0xBADBAD (size: 0) if specific cipher_store_index=0xBADBAD is used
	 * - Addr/size taken from internal array (if previously filled by ENCRYPT process)
	 */
	args.mac_size          = READ_VALUE(fp, uint32_t);

	/* In case of MAC verification with bit granularity,
	 * get the mac_size_bytes in a different way
	 */
	if ((args.flags & HSM_OP_MAC_ONE_GO_FLAGS_MAC_LENGTH_IN_BITS) &&
	    (!(args.flags & HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION))) {
		mac_size_bytes = args.mac_size / 8;
		if (args.mac_size % 8)
			mac_size_bytes++;
		if (mac_size_bytes > 16 &&
		    (args.algorithm & HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC)) {
			/* In case of CMAC, if mac_size in bytes is greater than the max
			 * allowed, i.e. testing boundary, then set the mac_size_bytes
			 * to 16. This will avoid issues when reading the MAC buffer
			 */
			mac_size_bytes = 16;
		}
	} else {
		if (args.mac_size == BAD_0)
			/* Test null mac_size */
			mac_size_bytes = 0;
		else
			mac_size_bytes = args.mac_size;
	}

	args.mac = READ_INPUT_BUFFER(fp, mac_size_bytes);

	if (!(args.flags & HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION)) {
		/* MAC Verification */
		if (args.flags & HSM_OP_MAC_ONE_GO_FLAGS_MAC_LENGTH_IN_BITS) {
			/* Handling bit granularity */
			if (args.mac_size == 0) {
				/* Only in case of negative test mac_size = 0
				 * and bit granularity is selected
				 */
				slt_print(SLT_INFO,
					  "Using bit granularity with 0 mac size\n");
			} else {
				/* mac_size has a good value, 2 possibilities then */
				if (!args.mac) {
					/* Verification with a mac already stored */
					slt_print(SLT_INFO, "Using stored mac\n");
					args.mac = testCtx->mac_ptr[mac_store_index];
				} else {
					/* Verification with an injected mac */
					slt_print(SLT_INFO, "Using injected mac\n");
				}
			}
		} else {
			/* Handling byte granularity */
			if (mac_store_index == BAD_VAL) {
				/* Test bad mac address */
				args.mac = (uint8_t *)BAD_VAL;
				args.mac_size = DUMMY_BUF_SIZE;
			} else if (mac_store_index == BAD_0) {
				/* Test bad mac address */
				args.mac = NULL;
				args.mac_size = DUMMY_BUF_SIZE;
			} else if (args.mac_size == BAD_0) {
				/* Test null, requires a pointer to the mac though */
				args.mac_size = 0;
				args.mac = dummy_buf;
			} else if (args.mac_size == 0) {
				args.mac = testCtx->mac_ptr[mac_store_index];
				args.mac_size = testCtx->mac_size[mac_store_index];
			}
		}
	} else {
		/* MAC Generation */
		if (mac_store_index == BAD_VAL) {
			/* Test bad mac address */
			args.mac_size = DUMMY_BUF_SIZE;
			args.mac = (uint8_t *)BAD_ADDR;
		} else if (mac_store_index == BAD_0) {
			/* Test bad mac address */
			args.mac = NULL;
			args.mac_size = DUMMY_BUF_SIZE;
		} else if (args.mac_size == BAD_0) {
			/* Test null size, it requires a pointer to the mac though */
			args.mac_size = 0;
			args.mac = dummy_buf;
		} else {
			/* No special handing required for output buffer */
		}
	}

	hsm_mac_verification_status_t *status =
		(hsm_mac_verification_status_t *)READ_OUTPUT_BUFFER
			(fp, sizeof(hsm_mac_verification_status_t));

	hsm_err_t err = hsm_mac_one_go(testCtx->hdl[index], &args, status);

	READ_CHECK_VALUE(testCtx, fp, err);

#ifdef CAVP_SUPPORT
	if (args.flags & HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION)
		DISPLAY_BUFFER(args.mac, mac_size_bytes);
#endif

	if (err == HSM_NO_ERROR) {
		READ_CHECK_BUFFER(testCtx, fp, args.mac, mac_size_bytes);
		if (args.flags & HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION) {
			testCtx->mac_size[mac_store_index] = args.mac_size;
			testCtx->mac_ptr[mac_store_index] = args.mac;
		} else {
			uint8_t *status_byte = (uint8_t *)status;

			DISPLAY_BUFFER(status_byte,
				       sizeof(hsm_mac_verification_status_t));
			READ_CHECK_BUFFER(testCtx, fp, status_byte,
					  sizeof(hsm_mac_verification_status_t));
		}
	}

	return fails;
}
