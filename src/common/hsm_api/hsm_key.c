/*
 * Copyright 2022 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#include <stddef.h>
#include <stdio.h>

#include "internal/hsm_key.h"

uint32_t set_key_type_n_sz(hsm_key_type_t key_type,
			   hsm_bit_key_sz_t *key_sz,
			   hsm_psa_key_type_t *psa_key_type,
			   hsm_pubkey_type_t *pkey_type,
			   uint16_t *byte_key_size)
{
	int ret = HSM_KEY_OP_SUCCESS;
	hsm_bit_key_sz_t loc_key_sz;
	hsm_psa_key_type_t loc_psa_key_type;
	uint16_t loc_byte_key_size = 0;
	hsm_pubkey_type_t loc_pkey_type = 0;

	switch (key_type) {
	case HSM_KEY_TYPE_HMAC_224:
		loc_key_sz = HSM_KEY_SIZE_HMAC_224;
		loc_psa_key_type = HSM_KEY_TYPE_HMAC;
		break;
	case HSM_KEY_TYPE_HMAC_256:
		loc_key_sz = HSM_KEY_SIZE_HMAC_256;
		loc_psa_key_type = HSM_KEY_TYPE_HMAC;
		break;
	case HSM_KEY_TYPE_HMAC_384:
		loc_key_sz = HSM_KEY_SIZE_HMAC_384;
		loc_psa_key_type = HSM_KEY_TYPE_HMAC;
		break;
	case HSM_KEY_TYPE_HMAC_512:
		loc_key_sz = HSM_KEY_SIZE_HMAC_512;
		loc_psa_key_type = HSM_KEY_TYPE_HMAC;
		break;
	case HSM_KEY_TYPE_AES_128:
		loc_key_sz = HSM_KEY_SIZE_AES_128;
		loc_psa_key_type = HSM_KEY_TYPE_AES;
		break;
	case HSM_KEY_TYPE_AES_192:
		loc_key_sz = HSM_KEY_SIZE_AES_192;
		loc_psa_key_type = HSM_KEY_TYPE_AES;
		break;
	case HSM_KEY_TYPE_AES_256:
		loc_key_sz = HSM_KEY_SIZE_AES_256;
		loc_psa_key_type = HSM_KEY_TYPE_AES;
		break;
	case HSM_KEY_TYPE_SM4_128:
		loc_key_sz = HSM_KEY_SIZE_SM4_128;
		loc_psa_key_type = HSM_KEY_TYPE_SM4;
		break;
	case HSM_KEY_TYPE_RSA_2048:
		loc_key_sz = HSM_KEY_SIZE_RSA_2048;
		loc_psa_key_type = HSM_KEY_TYPE_RSA;
		loc_pkey_type = HSM_PUBKEY_TYPE_RSA;
		loc_byte_key_size = (HSM_KEY_SIZE_RSA_2048 >> 3);
		break;
	case HSM_KEY_TYPE_RSA_4096:
		loc_key_sz = HSM_KEY_SIZE_RSA_4096;
		loc_psa_key_type = HSM_KEY_TYPE_RSA;
		loc_pkey_type = HSM_PUBKEY_TYPE_RSA;
		loc_byte_key_size = (HSM_KEY_SIZE_RSA_4096 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_224:
		loc_key_sz = HSM_KEY_SIZE_ECC_BP_R1_224;
		loc_psa_key_type = HSM_KEY_TYPE_ECC_BP_R1;
		loc_pkey_type = HSM_PUBKEY_TYPE_ECC_BP_R1;
		loc_byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_R1_224 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256:
		loc_key_sz = HSM_KEY_SIZE_ECC_BP_R1_256;
		loc_psa_key_type = HSM_KEY_TYPE_ECC_BP_R1;
		loc_pkey_type = HSM_PUBKEY_TYPE_ECC_BP_R1;
		loc_byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_R1_256 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_320:
		loc_key_sz = HSM_KEY_SIZE_ECC_BP_R1_320;
		loc_psa_key_type = HSM_KEY_TYPE_ECC_BP_R1;
		loc_pkey_type = HSM_PUBKEY_TYPE_ECC_BP_R1;
		loc_byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_R1_320 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384:
		loc_key_sz = HSM_KEY_SIZE_ECC_BP_R1_384;
		loc_psa_key_type = HSM_KEY_TYPE_ECC_BP_R1;
		loc_pkey_type = HSM_PUBKEY_TYPE_ECC_BP_R1;
		loc_byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_R1_384 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_512:
		loc_key_sz = HSM_KEY_SIZE_ECC_BP_R1_512;
		loc_psa_key_type = HSM_KEY_TYPE_ECC_BP_R1;
		loc_pkey_type = HSM_PUBKEY_TYPE_ECC_BP_R1;
		loc_byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_R1_512 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_NIST_P224:
		loc_key_sz = HSM_KEY_SIZE_ECC_NIST_224;
		loc_psa_key_type = HSM_KEY_TYPE_ECC_NIST;
		loc_pkey_type = HSM_PUBKEY_TYPE_ECC_NIST;
		loc_byte_key_size = 2 * (HSM_KEY_SIZE_ECC_NIST_224 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_NIST_P256:
		loc_key_sz = HSM_KEY_SIZE_ECC_NIST_256;
		loc_psa_key_type = HSM_KEY_TYPE_ECC_NIST;
		loc_pkey_type = HSM_PUBKEY_TYPE_ECC_NIST;
		loc_byte_key_size = 2 * (HSM_KEY_SIZE_ECC_NIST_256 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_NIST_P384:
		loc_key_sz = HSM_KEY_SIZE_ECC_NIST_384;
		loc_psa_key_type = HSM_KEY_TYPE_ECC_NIST;
		loc_pkey_type = HSM_PUBKEY_TYPE_ECC_NIST;
		loc_byte_key_size = 2 * (HSM_KEY_SIZE_ECC_NIST_384 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_NIST_P521:
		loc_key_sz = HSM_KEY_SIZE_ECC_NIST_521;
		loc_psa_key_type = HSM_KEY_TYPE_ECC_NIST;
		loc_pkey_type = HSM_PUBKEY_TYPE_ECC_NIST;
		loc_byte_key_size = 2 * (HSM_KEY_SIZE_ECC_NIST_521 >> 3) + 2;
		//Added 2 bytes due to 1 leftout bit during bits to bytes key size conversion
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_224:
		loc_key_sz = HSM_KEY_SIZE_ECC_BP_T1_224;
		loc_psa_key_type = HSM_KEY_TYPE_ECC_BP_T1;
		loc_pkey_type = HSM_PUBKEY_TYPE_ECC_BP_T1;
		loc_byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_T1_224 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256:
		loc_key_sz = HSM_KEY_SIZE_ECC_BP_T1_256;
		loc_psa_key_type = HSM_KEY_TYPE_ECC_BP_T1;
		loc_pkey_type = HSM_PUBKEY_TYPE_ECC_BP_T1;
		loc_byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_T1_256 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_320:
		loc_key_sz = HSM_KEY_SIZE_ECC_BP_T1_320;
		loc_psa_key_type = HSM_KEY_TYPE_ECC_BP_T1;
		loc_pkey_type = HSM_PUBKEY_TYPE_ECC_BP_T1;
		loc_byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_T1_320 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384:
		loc_key_sz = HSM_KEY_SIZE_ECC_BP_T1_384;
		loc_psa_key_type = HSM_KEY_TYPE_ECC_BP_T1;
		loc_pkey_type = HSM_PUBKEY_TYPE_ECC_BP_T1;
		loc_byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_T1_384 >> 3);
		break;
	default:
		loc_key_sz = 0;
		loc_psa_key_type = 0;
		loc_byte_key_size = 0;
		ret = HSM_KEY_OP_FAIL;
	}

	if (key_sz != NULL) {
		*key_sz = loc_key_sz;
	}

	if (psa_key_type != NULL) {
		*psa_key_type = loc_psa_key_type;
	}

	if (pkey_type != NULL) {
		*pkey_type = loc_pkey_type;
	}

	/* byte_key_size will be equal to zero, if HSM user donot want to
	 * export the Public Key.
	 */
	if (byte_key_size == NULL)
		return ret;

	if ((*byte_key_size != 0)
			&& (*byte_key_size != loc_byte_key_size)) {
		printf("Warning: In-Correct length for Public key\n");
		*byte_key_size = loc_byte_key_size;
	}

	return ret;
}
