// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdint.h>
#include <string.h>
#include <byteswap.h>

#include "hsm_api.h"
#include "test_importkey.h"

#include "common.h"
#include "openssl_testapi.h"

#if MT_SAB_IMPORT_KEY

#if PLAIN_KEY_IMPORT_NOT_SUPPORTED
static struct test_import_key_data  importkey_tdata;

static uint8_t set_length_field(uint8_t *len_buf, uint8_t len)
{
	uint32_t temp_len = len;
	uint8_t i = 0;

	if (len < TLV_LEN_GREATER_THAN_ONE_BYTE) {
		len_buf[0] = len;
	} else {
		len_buf[0] = TLV_LEN_GREATER_THAN_ONE_BYTE;
		do {
			len_buf[0]++;
		} while (len >>= 8);

		len = temp_len;
		do {
			len_buf[len_buf[0] - TLV_LEN_GREATER_THAN_ONE_BYTE - i] = len & 0xFF;
			i++;
		} while (len >>= 8);
	}
	return (i + 1);
}

int populate_tlv_data(uint8_t *tlv_buf, uint8_t tag,
		      uint32_t len, uint8_t *data)
{
	uint32_t next_tlv_data_buf_idx = 0;
	uint8_t len_of_len = sizeof(tag);

	tlv_buf[0] = tag;
	len_of_len = set_length_field(&(tlv_buf[sizeof(tag)]), len);
	memcpy(&tlv_buf[len_of_len + sizeof(tag)], data, len);

	next_tlv_data_buf_idx = sizeof(tag)
				+ len_of_len
				+ len;

	return next_tlv_data_buf_idx;
}

int populate_e2go_tlv(uint8_t *e2go_tlv_buf,
		      struct input_e2go_data *in_data,
		      void *in_sig_args, uint32_t sign_len,
		      uint32_t key_store_hdl)
{
	uint32_t next_tlv_data_buf_idx = 0;
	op_generate_sign_args_t *sig_gen_args;
	op_mac_one_go_args_t *mac_one_go;
	hsm_err_t hsmret;
	uint32_t bswap_32data;
	uint16_t bswap_16data;

	next_tlv_data_buf_idx += populate_tlv_data(&(e2go_tlv_buf[next_tlv_data_buf_idx]),
						   E2GO_TLV_MAGIC_TAG,
						   E2GO_TLV_MAGIC_LEN,
						   "edgelock2go");

	bswap_32data = bswap_32(in_data->key_id);
	next_tlv_data_buf_idx += populate_tlv_data(&(e2go_tlv_buf[next_tlv_data_buf_idx]),
					E2GO_TLV_KEY_ID_TAG,
					E2GO_TLV_KEY_ID_LEN,
					(uint8_t *) &bswap_32data);

	bswap_32data = bswap_32(in_data->perm_algo_id);
	next_tlv_data_buf_idx += populate_tlv_data(&(e2go_tlv_buf[next_tlv_data_buf_idx]),
					E2GO_TLV_KEY_ATTR_PERM_ALGO_TAG,
					E2GO_TLV_KEY_ATTR_PERM_ALGO_LEN,
					(uint8_t *) &bswap_32data);

	bswap_32data = bswap_32(in_data->key_usage);
	next_tlv_data_buf_idx += populate_tlv_data(&(e2go_tlv_buf[next_tlv_data_buf_idx]),
					E2GO_TLV_KEY_ATTR_USG_TAG,
					E2GO_TLV_KEY_ATTR_USG_LEN,
					(uint8_t *) &bswap_32data);

	bswap_16data = bswap_16(in_data->key_type);
	next_tlv_data_buf_idx += populate_tlv_data(&(e2go_tlv_buf[next_tlv_data_buf_idx]),
					E2GO_TLV_KEY_ATTR_TYPE_TAG,
					E2GO_TLV_KEY_ATTR_TYPE_LEN,
					(uint8_t *) &bswap_16data);

	bswap_32data = bswap_32(in_data->bit_key_sz);
	next_tlv_data_buf_idx += populate_tlv_data(&(e2go_tlv_buf[next_tlv_data_buf_idx]),
					E2GO_TLV_KEY_ATTR_BIT_SZ_TAG,
					E2GO_TLV_KEY_ATTR_BIT_SZ_LEN,
					(uint8_t *) &bswap_32data);

	bswap_32data = bswap_32(in_data->key_lifetime);
	next_tlv_data_buf_idx += populate_tlv_data(&(e2go_tlv_buf[next_tlv_data_buf_idx]),
					E2GO_TLV_KEY_ATTR_LIFETIME_TAG,
					E2GO_TLV_KEY_ATTR_LIFETIME_LEN,
					(uint8_t *) &bswap_32data);

	bswap_32data = bswap_32(in_data->import_key_lc);
	next_tlv_data_buf_idx += populate_tlv_data(&(e2go_tlv_buf[next_tlv_data_buf_idx]),
					E2GO_TLV_IMPORTED_KEY_LC_TAG,
					E2GO_TLV_IMPORTED_KEY_LC_LEN,
					(uint8_t *) &bswap_32data);

	bswap_32data = bswap_32(in_data->wrap_key_id);
	next_tlv_data_buf_idx += populate_tlv_data(&(e2go_tlv_buf[next_tlv_data_buf_idx]),
					E2GO_TLV_WRAP_KEY_ID_TAG,
					E2GO_TLV_WRAP_KEY_ID_LEN,
					(uint8_t *) &bswap_32data);

	bswap_32data = bswap_32(in_data->wrapping_algo);
	next_tlv_data_buf_idx += populate_tlv_data(&(e2go_tlv_buf[next_tlv_data_buf_idx]),
					E2GO_TLV_WRAP_ALGO_TAG,
					E2GO_TLV_WRAP_ALGO_LEN,
					(uint8_t *) &bswap_32data);

	if (in_data->iv_size) {
		next_tlv_data_buf_idx += populate_tlv_data(&(e2go_tlv_buf[next_tlv_data_buf_idx]),
						E2GO_TLV_IV_TAG,
						16,
						in_data->iv);
	}

	bswap_32data = bswap_32(in_data->sign_key_id);
	next_tlv_data_buf_idx += populate_tlv_data(&(e2go_tlv_buf[next_tlv_data_buf_idx]),
					E2GO_TLV_SIGNING_KEY_ID_TAG,
					E2GO_TLV_SIGNING_KEY_ID_LEN,
					(uint8_t *) &bswap_32data);

	bswap_32data = bswap_32(in_data->signing_algo);
	next_tlv_data_buf_idx += populate_tlv_data(&(e2go_tlv_buf[next_tlv_data_buf_idx]),
					E2GO_TLV_SIGNING_ALGO_TAG,
					E2GO_TLV_SIGNING_ALGO_LEN,
					(uint8_t *) &bswap_32data);

	next_tlv_data_buf_idx += populate_tlv_data(&(e2go_tlv_buf[next_tlv_data_buf_idx]),
					E2GO_TLV_KEY_BLOB_TAG,
					32,//in_data->key_blob_len,
					(uint8_t *) in_data->key_blob);

	/* Update the Tag and length for the signature before generating the
	 * Signature.
	 */
	e2go_tlv_buf[next_tlv_data_buf_idx] = E2GO_TLV_SIGNATURE_TAG;
	next_tlv_data_buf_idx++;
	next_tlv_data_buf_idx += set_length_field(&e2go_tlv_buf[next_tlv_data_buf_idx], sign_len);

	 /* TBD: As per document, it ECDSA P256, which is not a PSA compliant.*/
	if (in_data->signing_algo == IMPORT_ALGO_ECDSA) {
		sig_gen_args = (op_generate_sign_args_t *) in_sig_args;
		sig_gen_args->message = e2go_tlv_buf;
		sig_gen_args->message_size = next_tlv_data_buf_idx;
		sig_gen_args->signature = (uint8_t *) &e2go_tlv_buf[next_tlv_data_buf_idx];
		sig_gen_args->signature_size = sign_len;
		hsmret = hsm_do_sign(key_store_hdl, sig_gen_args);
		if (hsmret) {
			printf("hsm_do_sign failed ret:0x%x\n", hsmret);
			return -1;
		}
	} else if (in_data->signing_algo == IMPORT_ALGO_CMAC) {
		mac_one_go = (op_mac_one_go_args_t *) in_sig_args;
		mac_one_go->payload = e2go_tlv_buf;
		mac_one_go->payload_size = next_tlv_data_buf_idx;
		mac_one_go->mac_size = sign_len;
		mac_one_go->mac = (uint8_t *) &e2go_tlv_buf[next_tlv_data_buf_idx];
		hsmret = hsm_do_mac(key_store_hdl, mac_one_go);
		if (hsmret) {
			printf("hsm_do_mac failed ret:0x%x\n", hsmret);
			return -1;
		}
	}
	next_tlv_data_buf_idx += sign_len;

	if (in_data->wrapping_algo != IMPORT_ALGO_NONE) {
		printf("---------------------------------------------------\n");
		printf("E2go TLV Input buffer of length = %d:\n\n", next_tlv_data_buf_idx);
		hexdump_bb(e2go_tlv_buf, next_tlv_data_buf_idx);
		printf("---------------------------------------------------\n");
	}

	return next_tlv_data_buf_idx;
}

static int populate_wrapkey_e2gostruct(hsm_hdl_t sess_hdl,
				   struct input_e2go_data *in_data_for_wrap_key,
				   struct test_import_key_data *ik_tdata)
{
	op_get_random_args_t rng_get_random_args = {0};
	hsm_err_t err;

	/*
	 * Import a known wrap key with Key Import ELE FW API
	 * that will be used to unwrap the key blob present
	 * in TLV for next key importation operations.
	 *
	 * Import this key with the following TLV configuration:
	 * - Wrap algo = NONE (the key is imported in plaintext);
	 * - Wrap key ID = 0; (to be allocated by FW.)
	 * - Signature algo = CMAC_KEY_ID permitted algorithm;
	 * - Signature key ID = CMAC_KEY_ID.
	 *
	 * Example of wrap key to import:
	 * - Key type = AES;
	 * - Key size bits = 256;
	 * - Key permitted algorithm = KEK CBC;
	 *
	 *   (In FW code, there is a check for KEY_USAGE to be DECRYPT only
	 *   this key is used for unwraping other keys.)
	 * - Key usage = DECRYPT;
	 *
	 * - Lifetime = Internal Volatile;
	 * - Key ID = WRAP_KEY_ID.
	 */

	/* Generating a new wrap key */
	in_data_for_wrap_key->key_id = 0;
	in_data_for_wrap_key->perm_algo_id = PERMITTED_ALGO_OTH_KEK_CBC;
	in_data_for_wrap_key->key_type = HSM_KEY_TYPE_AES;
	in_data_for_wrap_key->key_usage = HSM_KEY_USAGE_DECRYPT;
	in_data_for_wrap_key->bit_key_sz = 256;
	in_data_for_wrap_key->key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	in_data_for_wrap_key->import_key_lc = 0x1;
	in_data_for_wrap_key->wrap_key_id = 0;
	in_data_for_wrap_key->wrapping_algo = IMPORT_ALGO_NONE;
	in_data_for_wrap_key->iv_size = 0;
	in_data_for_wrap_key->key_blob_len = in_data_for_wrap_key->bit_key_sz >> 3;

	in_data_for_wrap_key->sign_key_id = ik_tdata->sign_key_id;
	in_data_for_wrap_key->signing_algo = ik_tdata->signing_algo;

	/* Generating the RNG number as a wrap key.
	 * Storing in the key_blob.
	 */
	rng_get_random_args.random_size = in_data_for_wrap_key->key_blob_len;
	rng_get_random_args.output = in_data_for_wrap_key->key_blob;
	err = hsm_do_rng(sess_hdl, &rng_get_random_args);

	if (err != HSM_NO_ERROR) {
		printf("Failure while generating IV.\n");
		return 0;
	}
	/* Keeping the key_blob as plain, without wraping the
	 * key with another key.
	 * Leaving the key_blob buffer unchanged.
	 */
	ik_tdata->wrap_key_sz = in_data_for_wrap_key->key_blob_len;
	memcpy(ik_tdata->wrap_key_buf, in_data_for_wrap_key->key_blob,
		in_data_for_wrap_key->key_blob_len);

	return 0;
}

/* Validate the attributes of the signing key.
 * before importing the key.
 */
static uint32_t import_key(hsm_hdl_t key_store_hdl,
			hsm_hdl_t key_mgmt_hdl,
			struct input_e2go_data *in_data,
			struct test_import_key_data *ik_tdata)
{
	uint8_t buf[256];
	uint32_t sign_size = 0;
	op_import_key_args_t args;
	op_generate_sign_args_t sig_gen_args = {0};
	op_mac_one_go_args_t mac_one_go = {0};
	op_get_key_attr_args_t keyattr_args;
	hsm_err_t hsmret;
	uint32_t import_key_id;
	void *gen_sign_api = NULL;

	memset(&keyattr_args, 0, sizeof(keyattr_args));
	keyattr_args.key_identifier = ik_tdata->sign_key_id;
	hsmret = hsm_get_key_attr(key_mgmt_hdl, &keyattr_args);

	if (hsmret != HSM_NO_ERROR) {
		printf("hsm_get_key_attr failed:0x%x\n", hsmret);
		printf("Not a Valid Key Identifier.");
		printf(" Not proceeding for the import.\n");
		return 0;
	}

	if ((keyattr_args.permitted_algo != PERMITTED_ALGO_CMAC)
		&& ((keyattr_args.permitted_algo != HSM_KEY_TYPE_ECC_NIST)
		   /* TBD: As per document, it ECDSA P256, which is not a PSA compliant.*/
		   || (keyattr_args.permitted_algo != ALGO_ECDSA_SHA256))) {
		printf("Unsupported Permited Algo. Not a Valid Key Identifier.");
		printf(" Not proceeding for the import.\n");
		return 0;
	}

	if (keyattr_args.key_usage & (HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG)
			!= (HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG)) {
		printf("Invalid Key-Usage. Not a Valid Key Identifier.");
		printf(" Not proceeding for the import.\n");
		return 0;
	}

	if (keyattr_args.permitted_algo == PERMITTED_ALGO_CMAC) {
		mac_one_go.key_identifier = ik_tdata->sign_key_id;
		mac_one_go.algorithm = PERMITTED_ALGO_CMAC;
		mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
		sign_size = 16;
		gen_sign_api = &mac_one_go;
	} else if (keyattr_args.key_type == HSM_KEY_TYPE_ECC_NIST) {
		sig_gen_args.key_identifier = ik_tdata->sign_key_id;
		sig_gen_args.scheme_id = HSM_SIGNATURE_SCHEME_ECDSA_SHA256;
		sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;
		sign_size = 0;
		gen_sign_api = &sig_gen_args;
	}

	args.key_identifier = 0;
	args.input_size = populate_e2go_tlv(buf, in_data,
					    gen_sign_api, sign_size,
					    key_store_hdl);

	if (args.input_size < 0) {
		printf("Failure generating E2GO TLV payload.\n");
		return 0;
	}
	args.input_lsb_addr = buf;
	args.flags = HSM_OP_IMPORT_KEY_INPUT_E2GO_TLV;

	hsmret = hsm_import_key(key_mgmt_hdl, &args);
	if (hsmret)
		printf("Failure[0%x] in HSM Import KEy API.\n", hsmret);
	import_key_id = args.key_identifier;

	return import_key_id;
}

int test_import_key_e2gotlv(struct input_e2go_data *in_data,
			    hsm_hdl_t sess_hdl,
			    hsm_hdl_t key_store_hdl,
			    hsm_hdl_t key_mgmt_hdl,
			    uint32_t key_size,
			    uint8_t *key_buf,
			    uint32_t *importkey_id)
{
	op_generate_key_args_t key_gen_args = {0};
	op_get_random_args_t rng_get_random_args = {0};
	hsm_err_t hsmret;
	hsm_err_t err;

	if (importkey_tdata.is_set == false) {
		struct input_e2go_data in_data_for_wrap_key = {0};

		memset(&key_gen_args, 0, sizeof(op_generate_key_args_t));
		// Key type = AES;
		// Key size bits = 256;
		// Key permitted algorithm = CMAC;
		// Key usage = SIGN MESSAGE | VERIFY MESSAGE;
		// Lifetime = Internal Volatile;
		// Key ID = CMAC_KEY_ID.
		importkey_tdata.sign_key_id = 0;
		importkey_tdata.signing_algo = IMPORT_ALGO_CMAC;

		key_gen_args.key_identifier = &importkey_tdata.sign_key_id;
		key_gen_args.key_type = HSM_KEY_TYPE_AES;
		key_gen_args.key_group = 1;
		key_gen_args.bit_key_sz = 256;
		key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
		key_gen_args.key_usage = HSM_KEY_USAGE_SIGN_MSG
						| HSM_KEY_USAGE_VERIFY_MSG;
		key_gen_args.permitted_algo = PERMITTED_ALGO_CMAC;
		key_gen_args.key_lifecycle = 0;

		hsmret = hsm_generate_key(key_mgmt_hdl, &key_gen_args);

		if (hsmret)
			printf("hsm_generate_key ret:0x%x\n", hsmret);

		populate_wrapkey_e2gostruct(sess_hdl, &in_data_for_wrap_key, &importkey_tdata);
		importkey_tdata.wrap_key_id = import_key(key_store_hdl,
							key_mgmt_hdl,
							&in_data_for_wrap_key,
							&importkey_tdata);
		if (importkey_tdata.wrap_key_id == 0) {
			printf("Failure adding the WRAP Key to the HSM.\n");
			return -1;
		}
		importkey_tdata.is_set = true;

		printf("---------------------------------------------------\n");
		printf("Wrap Key_id   = %x\n", importkey_tdata.wrap_key_id);
		printf("Wrap Key size = %d\n", importkey_tdata.wrap_key_sz);
		printf("Wrap Key      :\n\n");
		hexdump_bb(importkey_tdata.wrap_key_buf,
				importkey_tdata.wrap_key_sz);
		printf("---------------------------------------------------\n");
	}

	if (in_data->wrap_key_id == 0)
		in_data->wrap_key_id = importkey_tdata.wrap_key_id;
	if (in_data->sign_key_id == 0)
		in_data->sign_key_id = importkey_tdata.sign_key_id;
	if (in_data->signing_algo == 0)
		in_data->signing_algo = importkey_tdata.signing_algo;


	if (openSSL_Encryption(key_buf, key_size,
			       importkey_tdata.wrap_key_buf,
			       importkey_tdata.wrap_key_sz,
			       in_data->key_blob, &in_data->key_blob_len,
			       ALGO_CIPHER_CBC_NO_PAD, in_data->iv,
			       in_data->iv_size)) {
		printf("OpenSSL based encryption failed.\n");
		return -1;
	}

	/* Encrypting the plain key with the wrap key to generate a key_blob.
	 */
	printf("\nWrapped New Plain key to be imported of size = %d:\n\n",
				in_data->key_blob_len);
	hexdump_bb(in_data->key_blob, in_data->key_blob_len);


	*importkey_id = import_key(key_store_hdl,
				   key_mgmt_hdl,
				   in_data,
				   &importkey_tdata);
	return 0;
}

int test_import_key(hsm_hdl_t sess_hdl,
		hsm_hdl_t key_store_hdl,
		hsm_hdl_t key_mgmt_hdl,
		uint32_t key_size,
		uint8_t *key_buf,
		op_import_key_args_t *args)
{
	struct input_e2go_data in_data = {0};
	op_get_random_args_t rng_get_random_args = {0};
	hsm_err_t err;
	int ret = -1;

	/* Generate the Key if the key buffer is empty.
	 * Memory should be allocated for key buf
	 * by its caller.
	 */
	if (key_buf[0] == 0x0 && key_buf[1] == 0x0) {
		/* Generating the RNG number as key.*/
		rng_get_random_args.random_size = key_size;
		rng_get_random_args.output = key_buf;
		err = hsm_do_rng(sess_hdl, &rng_get_random_args);

		if (err != HSM_NO_ERROR) {
			printf("Failed[0x%x] to generate new key to be imported.\n",
				err);
			return ret;
		}
	}

	if ((args->flags & HSM_OP_IMPORT_KEY_INPUT_E2GO_TLV)
			== HSM_OP_IMPORT_KEY_INPUT_E2GO_TLV) {
		/* Importing the new Key stored in key_buf */

		printf("\n---------------------------------------------------\n");
		printf("Import Key - E2go TLV\n");
		printf("---------------------------------------------------\n\n");

		printf("New Plain key to be imported of size = %d:\n", key_size);
		hexdump_bb(key_buf, key_size);

		in_data.key_id = 0;
		in_data.sign_key_id = 0;
		in_data.wrap_key_id = 0;
		in_data.signing_algo = 0;
		in_data.perm_algo_id = PERMITTED_ALGO_ECB_NO_PADDING
					| PERMITTED_ALGO_CBC_NO_PADDING;
		in_data.key_type = HSM_KEY_TYPE_AES;
		in_data.key_usage = HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT;
		in_data.bit_key_sz = key_size << 3;
		in_data.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
		in_data.import_key_lc = 0x1;
		in_data.wrapping_algo = IMPORT_ALGO_AES_CBC;
		in_data.iv_size = 16;
		rng_get_random_args.random_size = in_data.iv_size;
		rng_get_random_args.output = in_data.iv;
		err = hsm_do_rng(sess_hdl, &rng_get_random_args);
		if (err != HSM_NO_ERROR) {
			printf("Failurep[0x%x] while generating IV.\n", err);
			return ret;
		}

		ret = test_import_key_e2gotlv(&in_data, sess_hdl, key_store_hdl,
						key_mgmt_hdl, key_size,
						key_buf, &args->key_identifier);
		if (ret)
			printf ("Test Failed for E2Go TLV based Import Key.\n");

		printf("Import Key Success, with Key Id as: 0x%x\n",
			args->key_identifier);
		ret = 0;
	} else {
		printf("\n---------------------------------------------------\n");
		printf("Import Key - Signed Format not supported.\n");
		printf("---------------------------------------------------\n\n");

		ret = 0;
	}

	return ret;
}
#else
static long get_file_size(uint8_t *fname)
{
	long fsize = 0;
	FILE *fptr = fopen(fname, "r");

	if (fptr) {
		if (fseek(fptr, 0L, SEEK_END) == 0)
			/* Get the size of the file. */
			fsize = ftell(fptr);
		fsize = (fsize < 0) ? 0 : fsize;
		fclose(fptr);
	}

	return fsize;
}

static int read_fl_to_buf(uint8_t *fname, uint8_t *fbuf, long fsize)
{
	FILE *fptr = fopen(fname, "r");
	size_t nlen;

	if (fptr) {
		nlen = fread(fbuf, sizeof(char), fsize, fptr);
		if (ferror(fptr) != 0)
			printf("Error reading file.\n");
		else
			fbuf[nlen++] = '\0'; /* Just to be safe. */

		fclose(fptr);
	}
}

struct import_key_data {
	uint8_t *fname;
	uint32_t key_id;
};

uint32_t test_key_import(hsm_hdl_t key_mgmt_hdl, hsm_hdl_t key_store_hdl)
{
	uint8_t hash_data[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

	uint8_t iv_data[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

	uint8_t *import_key_buf;
	struct import_key_data imkd[] = {
		{
			.fname = "/usr/share/se/test_vectors/el2go_aes_test.blob",
			.key_id = 0x10000090,
		},
	};
	uint32_t import_key_len;
	op_import_key_args_t args;
	op_cipher_one_go_args_t cipher_args = {0};
	hsm_hdl_t cipher_hdl;
	uint8_t ciphered_data[32] = {0};
	uint8_t deciphered_data[32] = {0};
	hsm_err_t hsmret;

	import_key_len = get_file_size(imkd[0].fname);
	if (!import_key_len)
		return 0;

	import_key_buf = malloc(import_key_len + 1);
	if (!import_key_buf) {
		printf("No import key blob to test.\n");
		return 0;
	}
	if (read_fl_to_buf(imkd[0].fname, import_key_buf, import_key_len)) {
		printf("file empty: no Import key blob to test.\n");
		free(import_key_buf);
		return 0;
	}

	args.flags = HSM_OP_IMPORT_KEY_INPUT_E2GO_TLV;
	args.input_lsb_addr = import_key_buf;
	args.input_size = import_key_len;

	hsmret = hsm_import_key(key_mgmt_hdl, &args);
	if (hsmret) {
		if (hsmret == HSM_ID_CONFLICT) {
			printf("Warn: key is already imported.\n");
			args.key_identifier = imkd[0].key_id;
		} else {
			printf("Failure[0%x] in HSM Import Key API.\n", hsmret);
		}
	}
	free(import_key_buf);

	if (!args.key_identifier)
		return 0;

	printf("Imported Key ID = 0x%x\n", args.key_identifier);

	cipher_args.key_identifier = args.key_identifier;
	cipher_args.iv = NULL;
	cipher_args.iv_size = 0;
	cipher_args.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_ECB;
	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;
	cipher_args.input = hash_data;
	cipher_args.output = ciphered_data;
	cipher_args.input_size = sizeof(hash_data);
	cipher_args.output_size = sizeof(ciphered_data);

	hsmret = hsm_do_cipher(key_store_hdl, &cipher_args);
	if (hsmret)
		printf("hsm_cipher_one_go ret:0x%x\n", hsmret);

	cipher_args.flags = HSM_CIPHER_ONE_GO_FLAGS_DECRYPT;
	cipher_args.input = ciphered_data;
	cipher_args.output = deciphered_data;
	cipher_args.input_size = sizeof(ciphered_data);
	cipher_args.output_size = sizeof(deciphered_data);

	hsmret = hsm_do_cipher(key_store_hdl, &cipher_args);
	if (hsmret)
		printf("hsm_cipher_one_go ret:0x%x\n", hsmret);

	if (memcmp(hash_data, deciphered_data, sizeof(hash_data)) == 0)
		printf("\nDecrypted data matches encrypted data [PASS]\n");
	else
		printf("\nDecrypted data doesn't match encrypted data [FAIL]\n");

	return args.key_identifier;
}
#endif
#endif //MT_SAB_IMPORT_KEY
