/*
 * Copyright 2023 NXP
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

#ifndef HSM_GC_ACRYPTO_H
#define HSM_GC_ACRYPTO_H

#include "internal/hsm_key.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"

/**
 *	@defgroup group24 Generic Crypto: Asymmetric Crypto
 * @{
 */

//!< Algorithms to be used for the operations
typedef enum {
	HSM_GC_ACRYPTO_ALGO_ECDSA_SHA224 = ALGO_ECDSA_SHA224,
	HSM_GC_ACRYPTO_ALGO_ECDSA_SHA256 = ALGO_ECDSA_SHA256,
	HSM_GC_ACRYPTO_ALGO_ECDSA_SHA384 = ALGO_ECDSA_SHA384,
	HSM_GC_ACRYPTO_ALGO_ECDSA_SHA512 = ALGO_ECDSA_SHA512,
	HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_V15_SHA224 = ALGO_RSA_PKCS1_V15_SHA224,
	HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_V15_SHA256 = ALGO_RSA_PKCS1_V15_SHA256,
	HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_V15_SHA384 = ALGO_RSA_PKCS1_V15_SHA384,
	HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_V15_SHA512 = ALGO_RSA_PKCS1_V15_SHA512,
	HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_PSS_MGF1_SHA224 = ALGO_RSA_PKCS1_PSS_MGF1_SHA224,
	HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_PSS_MGF1_SHA256 = ALGO_RSA_PKCS1_PSS_MGF1_SHA256,
	HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_PSS_MGF1_SHA384 = ALGO_RSA_PKCS1_PSS_MGF1_SHA384,
	HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_PSS_MGF1_SHA512 = ALGO_RSA_PKCS1_PSS_MGF1_SHA512,
	HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_V15_CRYPT = ALGO_RSA_PKCS1_V15_CRYPT,
	HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_OAEP_SHA1 = ALGO_RSA_PKCS1_OAEP_SHA1,
	HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_OAEP_SHA224 = ALGO_RSA_PKCS1_OAEP_SHA224,
	HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_OAEP_SHA256 = ALGO_RSA_PKCS1_OAEP_SHA256,
	HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_OAEP_SHA384 = ALGO_RSA_PKCS1_OAEP_SHA384,
	HSM_GC_ACRYPTO_ALGO_RSA_PKCS1_OAEP_SHA512 = ALGO_RSA_PKCS1_OAEP_SHA512,
} hsm_op_gc_acrypto_algo_t;

//!< Operation modes
typedef enum {
	HSM_GC_ACRYPTO_OP_MODE_ENCRYPT  = 0x01,
	HSM_GC_ACRYPTO_OP_MODE_DECRYPT  = 0x02,
	HSM_GC_ACRYPTO_OP_MODE_SIGN_GEN = 0x03,
	HSM_GC_ACRYPTO_OP_MODE_SIGN_VER = 0x04,
} hsm_gc_acrypto_op_mode_t;

typedef uint8_t hsm_op_gc_acrypto_flags_t;
#define HSM_OP_GC_ACRYPTO_FLAGS_INPUT_MESSAGE \
	((hsm_op_gc_acrypto_flags_t)(1u << 0))

typedef uint32_t hsm_gc_acrypto_verification_status_t;
#define HSM_GC_ACRYPTO_VERIFICATION_SUCCESS \
		((hsm_gc_acrypto_verification_status_t)(0x5A3CC3A5u))
#define HSM_GC_ACRYPTO_VERIFICATION_FAILURE \
		((hsm_gc_acrypto_verification_status_t)(0x2B4DD4B2u))

typedef struct {
	//!< algorithm to use for the operation
	hsm_op_gc_acrypto_algo_t algorithm;
	//!< indicates the operation mode
	hsm_gc_acrypto_op_mode_t op_mode;
	//!< indicates operation flags
	hsm_op_gc_acrypto_flags_t flags;
	//!< key size in bits
	hsm_bit_key_sz_t bit_key_sz;
	//!< pointer to the data buffer 1:
	//	- plaintext in case of encryption/decryption op
	//	- digest or message in case of signature generation/verification op
	uint8_t *data_buff1;
	//!< pointer to the data buffer 2:
	//	- ciphertext in case of encryption/decryption op
	//	- signature in case of signature generation/verification op
	uint8_t *data_buff2;
	//!< size in bytes of data buffer 1
	uint32_t data_buff1_size;
	//!< size in bytes of data buffer 2
	uint32_t data_buff2_size;
	//!< pointer to the key modulus buffer
	uint8_t *key_buff1;
	//!< pointer the key exponent, either private or public
	//	-Encryption mode, public exponent
	//	-Decryption mode, private exponent
	//	-Signature Generation mode, private exponent
	//	-Signature Verification mode, public exponent
	uint8_t *key_buff2;
	//!< size in bytes of the key buffer 1
	uint16_t key_buff1_size;
	//!< size in bytes of the key buffer 2
	uint16_t key_buff2_size;
	//!< RSA label address
	//	-only used for OAEP encryption/decryption op mode and optional
	uint8_t *rsa_label;
	//!< RSA label size in bytes
	//	-only used for OAEP encryption/decryption op mode
	uint16_t rsa_label_size;
	//!< RSA salt length in bytes
	//	-only used for PSS signature algorithm scheme
	uint16_t rsa_salt_len;
	//!< expected plaintext length in bytes, returned by FW in case of
	//	DECRYPT operation mode
	uint32_t exp_plaintext_len;
	//!< signature verification status
	hsm_gc_acrypto_verification_status_t verification_status;
} op_gc_acrypto_args_t;

/**
 * This command is designed to perform the following operations:
 *	-Asymmetric crypto
 *		-encryption/decryption
 *		-signature generation/verification
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_gc_acrypto(hsm_hdl_t session_hdl, op_gc_acrypto_args_t *args);
/** @} end of generic crypto asymmetric crypto service flow */
#endif
