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

#include "internal/hsm_key.h"

uint32_t set_key_type_n_sz(hsm_key_type_t key_type,
			   hsm_bit_key_sz_t *key_sz,
			   hsm_psa_key_type_t *psa_key_type,
			   uint16_t *byte_key_size)
{
	int ret = HSM_KEY_OP_SUCCESS;
	*byte_key_size = 0;

	switch (key_type) {
	case HSM_KEY_TYPE_HMAC_224:
		*key_sz = HSM_KEY_SIZE_HMAC_224;
		*psa_key_type = HSM_KEY_TYPE_HMAC;
		break;
	case HSM_KEY_TYPE_HMAC_256:
		*key_sz = HSM_KEY_SIZE_HMAC_256;
		*psa_key_type = HSM_KEY_TYPE_HMAC;
		break;
	case HSM_KEY_TYPE_HMAC_384:
		*key_sz = HSM_KEY_SIZE_HMAC_384;
		*psa_key_type = HSM_KEY_TYPE_HMAC;
		break;
	case HSM_KEY_TYPE_HMAC_512:
		*key_sz = HSM_KEY_SIZE_HMAC_512;
		*psa_key_type = HSM_KEY_TYPE_HMAC;
		break;
	case HSM_KEY_TYPE_AES_128:
		*key_sz = HSM_KEY_SIZE_AES_128;
		*psa_key_type = HSM_KEY_TYPE_AES;
		break;
	case HSM_KEY_TYPE_AES_192:
		*key_sz = HSM_KEY_SIZE_AES_192;
		*psa_key_type = HSM_KEY_TYPE_AES;
		break;
	case HSM_KEY_TYPE_AES_256:
		*key_sz = HSM_KEY_SIZE_AES_256;
		*psa_key_type = HSM_KEY_TYPE_AES;
		break;
	case HSM_KEY_TYPE_SM4_128:
		*key_sz = HSM_KEY_SIZE_SM4_128;
		*psa_key_type = HSM_KEY_TYPE_SM4;
		break;
	case HSM_KEY_TYPE_RSA_2048:
		*key_sz = HSM_KEY_SIZE_RSA_2048;
		*psa_key_type = HSM_KEY_TYPE_RSA;
		*byte_key_size = (HSM_KEY_SIZE_RSA_2048 >> 3);
		break;
	case HSM_KEY_TYPE_RSA_4096:
		*key_sz = HSM_KEY_SIZE_RSA_4096;
		*psa_key_type = HSM_KEY_TYPE_RSA;
		*byte_key_size = (HSM_KEY_SIZE_RSA_4096 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_224:
		*key_sz = HSM_KEY_SIZE_ECC_BP_R1_224;
		*psa_key_type = HSM_KEY_TYPE_ECC_BP_R1;
		*byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_R1_224 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256:
		*key_sz = HSM_KEY_SIZE_ECC_BP_R1_256;
		*psa_key_type = HSM_KEY_TYPE_ECC_BP_R1;
		*byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_R1_256 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_320:
		*key_sz = HSM_KEY_SIZE_ECC_BP_R1_320;
		*psa_key_type = HSM_KEY_TYPE_ECC_BP_R1;
		*byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_R1_320 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384:
		*key_sz = HSM_KEY_SIZE_ECC_BP_R1_384;
		*psa_key_type = HSM_KEY_TYPE_ECC_BP_R1;
		*byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_R1_384 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_512:
		*key_sz = HSM_KEY_SIZE_ECC_BP_R1_512;
		*psa_key_type = HSM_KEY_TYPE_ECC_BP_R1;
		*byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_R1_512 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_NIST_P224:
		*key_sz = HSM_KEY_SIZE_ECC_NIST_224;
		*psa_key_type = HSM_KEY_TYPE_ECC_NIST;
		*byte_key_size = 2 * (HSM_KEY_SIZE_ECC_NIST_224 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_NIST_P256:
		*key_sz = HSM_KEY_SIZE_ECC_NIST_256;
		*psa_key_type = HSM_KEY_TYPE_ECC_NIST;
		*byte_key_size = 2 * (HSM_KEY_SIZE_ECC_NIST_256 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_NIST_P384:
		*key_sz = HSM_KEY_SIZE_ECC_NIST_384;
		*psa_key_type = HSM_KEY_TYPE_ECC_NIST;
		*byte_key_size = 2 * (HSM_KEY_SIZE_ECC_NIST_384 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_NIST_P521:
		*key_sz = HSM_KEY_SIZE_ECC_NIST_521;
		*psa_key_type = HSM_KEY_TYPE_ECC_NIST;
		*byte_key_size = 2 * (HSM_KEY_SIZE_ECC_NIST_521 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_224:
		*key_sz = HSM_KEY_SIZE_ECC_BP_T1_224;
		*psa_key_type = HSM_KEY_TYPE_ECC_BP_T1;
		*byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_T1_224 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_256:
		*key_sz = HSM_KEY_SIZE_ECC_BP_T1_256;
		*psa_key_type = HSM_KEY_TYPE_ECC_BP_T1;
		*byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_T1_256 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_320:
		*key_sz = HSM_KEY_SIZE_ECC_BP_T1_320;
		*psa_key_type = HSM_KEY_TYPE_ECC_BP_T1;
		*byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_T1_320 >> 3);
		break;
	case HSM_KEY_TYPE_ECDSA_BRAINPOOL_T1_384:
		*key_sz = HSM_KEY_SIZE_ECC_BP_T1_384;
		*psa_key_type = HSM_KEY_TYPE_ECC_BP_T1;
		*byte_key_size = 2 * (HSM_KEY_SIZE_ECC_BP_T1_384 >> 3);
		break;
	default:
		*key_sz = 0;
		*psa_key_type = 0;
		*byte_key_size = 0;
		ret = HSM_KEY_OP_FAIL;
	}

	return ret;
}
