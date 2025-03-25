// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef __test_hsm_cavp_support_H__
#define __test_hsm_cavp_support_H__

#include "hsm_exec.h"
#include "shx_test_macros.h"

/* CAVP operation result values */
#define CAVP_OPER_RES_UNUSED                0x00
#define CAVP_OPER_RES_SIG_VERIF_PASS        0x01
#define CAVP_OPER_RES_KAS_VERIF_PASS        0x02
#define CAVP_OPER_RES_KAS_VERIF_FAIL        0xFE
#define CAVP_OPER_RES_SIG_VERIF_FAIL        0xFF

/* CAVP function codes & parameter formats */
#define SAB_HSM_CAVP_FUNCTION_PRIV_KEY      (0x0001)
/*
 * Private key extraction:
 *  - session_handle = session handle
 *  - service_handle = key store handle
 *  - cavp_function = SAB_HSM_CAVP_FUNCTION_PRIV_KEY
 *  - key_id = key id
 *  - value1 = key type
 *  - value2 = <unused>
 *  - input_address = <unused>
 *  - output_address = buffer for private key
 *  - params_address = <unused>
 *  - input_size = 0
 *  - output_size = must match priv key size
 *  - params_size = 0
 *
 *  operation_result = CAVP_OPER_RES_UNUSED
 */

#define SAB_HSM_CAVP_FUNCTION_SIGN_VERIF      (0x0002)
/*
 * Signature verification:
 *  - session_handle = session handle
 *  - service_handle = <unused>
 *  - cavp_function = SAB_HSM_CAVP_FUNCTION_SIGN_VERIF
 *  - key_id = <unused>
 *  - value1 = <unused>
 *  - value2 = <unused>
 *  - input_address = buffer containing signature + message
 *  - output_address = <unused>
 *  - params_address = buffer containing params + keys
 *  - input_size = size of sig + msg buffer
 *  - output_size = 0
 *  - params_size = size of params buffer
 *
 *  input buffer format:
 *    signature
 *    message
 *
 *  params buffer format:
 *    byte 00: 0x00
 *    byte 01: 0x00
 *    byte 02: 0x00
 *    byte 03: Crypto scheme: RSA=0x21,  ECDSA=0x27
 *    byte 04: Hash algo: SHA256=0x00, SHA384=0x01, SHA512=0x02
 *    byte 05: Key/Curve Size:  P256=0x01, P384=0x02, P521=0x03; RSA2048=0x05,
				RSA3072=0x06, RSA4096=0x07
 *    byte 06: 0x00
 *    byte 07: 0x00
 *    bytes 08/09: sizeof(modulus or X), must match key/curve size
 *    bytes 10/11: sizeof(exponent or Y), must match key/curve size
 *    bytes 12 onwards: Modulus or X (big endian)
 *    after modulus or X: Exponent or Y (big endian)
 *
 *  operation_result = CAVP_OPER_RES_SIG_VERIF_PASS or CAVP_OPER_RES_SIG_VERIF_FAIL
 */

#define SAB_HSM_CAVP_FUNCTION_KBKDF_AES_256_CMAC_COUNTER     (0x0003)
/*
 * KBKDF AES-256 CMAC:
 *  - session_handle = session handle
 *  - service_handle = <unused>
 *  - cavp_function = SAB_HSM_CAVP_FUNCTION_KBKDF_AES_256_CMAC
 *  - key_id = <unused>
 *  - value1 = L size in bytes
 *  - value2 = <unused>
 *  - input_address = buffer containing KI
 *  - output_address = KO + fixed input data size (1 bytes) + fixed input data
 *  - params_address = <unused>
 *  - input_size = size of KI
 *  - output_size = >= L bytes + 1 byte + size of fixed input data
 *  - params_size = <unused>
 *
 *
 *  input buffer format:
 *    KI
 *
 *  operation_result = CAVP_OPER_RES_UNUSED
 */

#define SAB_HSM_CAVP_FUNCTION_DRBG_SHA      (0x0004)
/*
 * DRBG SHA verification
 *  - session_handle = session handle
 *  - service_handle = <unused>
 *  - cavp_function = SAB_HSM_CAVP_FUNCTION_DRBG_SHA
 *  - key_id = <unused>
 *  - value1 = <unused>
 *  - value2 = <unused>
 *  - input_address = buffer containing message
 *  - output_address = buffer containing hash
 *  - params_address = unused
 *  - input_size = size of message buffer
 *  - output_size = size of hash buffer
 *  - params_size = 0
 *
 *  operation_result = CAVP_OPER_RES_UNUSED
 */

#define SAB_HSM_CAVP_FUNCTION_DRBG     (0x0005)
/*
 * DRBG:
 * - session_handle = session handle
 * - service_handle = <unused>
 * - cavp_function = SAB_HSM_CAVP_FUNCTION_DRBG
 * - key_id = <unused>
 * - value1 = prediction resistance
 * - value2 = <unused>
 * - input_address = input buffer - see description below
 * - output_address = returned bits value
 * - params_address = input params address
 * - input_size = varies
 * - output_size = ReturnedBitsLen expressed in bytes
 * - params_size = 20 bytes
 *
 *
 * param buffer format:
 *   typedef struct {
 *       uint32_t entropy_size;
 *       uint32_t nonce_size;
 *       uint32_t pers_string_size;
 *       uint32_t additional_input_size;
 *       uint32_t return_bit_size;
 *   } cavp_drbg_params ;
 *
 * Input buffer format:
 *  Prediction resistance = 0
 *      EntropyInput || Nonce || PersonalizationString || EntropyInputReseed ||
		AdditionalInputReseed || AdditionalInput1 || AdditionalInput2
 *
 *  Prediction resistance = 1
 *      EntropyInput || Nonce || PersonalizationString || AdditionalInput1 ||
		EntropyInputPR1 || AdditionalInput2 || EntropyInputPR2
 *
 *  operation_result = CAVP_OPER_RES_UNUSED
 */

typedef struct {
	uint32_t entropy_size;
	uint32_t nonce_size;
	uint32_t pers_string_size;
	uint32_t additional_input_size;
	uint32_t return_bit_size;
} cavp_drbg_params;

#define SAB_HSM_CAVP_FUNCTION_GET_ENTROPY      (0x0006)
/*
 * Private key extraction:
 *  - session_handle = session handle
 *  - service_handle = Unused
 *  - cavp_function = SAB_HSM_CAVP_FUNCTION_GET_ENTROPY
 *  - key_id = <unused>
 *  - value1 = bit field for entropy control (start/stop/restart)
 *  - value2 = ent_dly (only used for noise counter tests)
 *  - input_address = <unused>
 *  - output_address = buffer for entropy data
 *  - params_address = <unused>
 *  - input_size = 0
 *  - output_size = size of entropy data buffer (64 byte multiple)
 *  - params_size = 0
 *
 *  operation_result = number of cases of TRNG ERR bit set (forcing retries)
 */
#define GET_ENTROPY_FIELD_START         0x01
#define GET_ENTROPY_FIELD_STOP          0x02
#define GET_ENTROPY_FIELD_RESTART       0x04
#define GET_ENTROPY_FIELD_WAITFORVAL    0x08
#define GET_ENTROPY_FIELD_NOISE_INIT    0x10
#define GET_ENTROPY_FIELD_NOISE_COUNTER 0x20
#define GET_ENTROPY_FIELD_NOISE_DEINIT  0x40
#define GET_ENTROPY_FIELD_ERROR_INIT    0x80
#define GET_ENTROPY_FIELD_ERROR_COUNTER 0x100
#define GET_ENTROPY_FIELD_ERROR_DEINIT  0x200
#define GET_ENTROPY_FIELD_INIT_TIMES    0x400
#define GET_ENTROPY_FIELD_FREQUENCY     0x800
#define GET_ENTROPY_FIELD_ERR_VARIANCE  0x4000
#define GET_ENTROPY_FIELD_DXL_V2XS      0x8000

#define SAB_HSM_ACVP_FUNCTION_TLS_KDF      (0x0007)

/*
 * TLS KDF:
 *  - session_handle = session handle
 *  - service_handle = Unused
 *  - cavp_function = SAB_HSM_ACVP_FUNCTION_TLS_KDF
 *  - key_id = <unused>
 *  - value1 = pre_master_secret length
 *  - value2 = requested key_block length
 *  - input_address = KDF input buffer - see format below
 *  - output_address = KDF output buffer - see format below
 *  - params_address = <unused>
 *  - input_size = 136 + pre_master_secret length
 *  - output_size = 48 + key_block length
 *  - params_size = 0
 *
 *  input buffer format:
 *    clientHello_random || serverHello_random || server_random ||
 *          client_random || hash_algo || pre_master_secret
 *  Note: random values are 32 bytes long and provided in the order stated above
 *  Note: hash_algo coded on 1 byte but followed by 7 00's to maintain DMA alignment
 *          hash_algo = AHAB_SHA2_256 (0x11) or AHAB_SHA2_384 (0x12)
 *
 *  output buffer format:
 *    master_secret || key_block
 *  Note: master_secret is 48 bytes long
 *
 *  operation_result = CAVP_OPER_RES_UNUSED
 */
#define CAVP_HASH_ALGO_FIELD_SIZE			8

#define SAB_HSM_CAVP_FUNCTION_ECDH_DEPRICATED		(0x0008)

#define SAB_HSM_ACVP_FUNCTION_SHA256_KDF		(0x0009)

/*
 * SHA256 one-step kdf:
 *  - session_handle = session handle
 *  - service_handle = Unused
 *  - cavp_function = SAB_HSM_ACVP_FUNCTION_SHA256_KDF
 *  - key_id = <unused>
 *  - value1 = <unused>
 *  - value2 = <unused>
 *  - input_address = z input buffer
 *  - output_address = dkm output buffer
 *  - params_address = parameter buffer (see format below)
 *  - input_size = variable
 *  - output_size = variable
 *  - params_size = variable
 *
 *  parameter buffer format:
 *    uPartyInfo || vPartyInfo
 *
 *  operation_result = CAVP_OPER_RES_UNUSED
 */

#define SAB_HSM_ACVP_FUNCTION_KAS_ECC_SSC_AFT         (0x000A)
/*
 * KAS-EEC-SSC for AFT mode:
 *  - session_handle = session handle
 *  - service_handle = Unused
 *  - cavp_function = SAB_HSM_ACVP_FUNCTION_KAS_ECC_SSC_AFT
 *  - key_id = <unused>
 *  - value1 = key_type
 *  - value2 = <unused>
 *  - input_address = server public key
 *  - output_address = see format below
 *  - params_address = <unused>
 *  - input_size = 64 (for P-256) or 96 (for P-384)
 *  - output_size = 96 (for P-256) or 144 (for P-384)
 *  - params_size = 0
 *
 *  Note: key_type = SAB_HSM_KEY_TYPE_ECDSA_NIST_P256 (0x02)
 *                or SAB_HSM_KEY_TYPE_ECDSA_NIST_P384 (0x03)
 *                or SAB_HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256 (0x13)
 *                or SAB_HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384 (0x15)
 *
 *  output buffer format:
 *    IUT public key || shared_secret
 *
 *  operation_result = CAVP_OPER_RES_UNUSED
 */

#define SAB_HSM_ACVP_FUNCTION_KAS_ECC_SSC_VAL         (0x000B)
/*
 * KAS-EEC-SSC for VAL mode:
 *  - session_handle = session handle
 *  - service_handle = Unused
 *  - cavp_function = SAB_HSM_ACVP_FUNCTION_KAS_ECC_SSC_VAL
 *  - key_id = <unused>
 *  - value1 = key_type
 *  - value2 = <unused>
 *  - input_address = see format below
 *  - output_address = <unused>
 *  - params_address = <unused>
 *  - input_size = 192 (for P-256) or 288 (for P-384)
 *  - output_size = 0
 *  - params_size = 0
 *
 *  Note: key_type = SAB_HSM_KEY_TYPE_ECDSA_NIST_P256 (0x02)
 *                or SAB_HSM_KEY_TYPE_ECDSA_NIST_P384 (0x03)
 *                or SAB_HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_256 (0x13)
 *                or SAB_HSM_KEY_TYPE_ECDSA_BRAINPOOL_R1_384 (0x15)
 *
 *  input buffer format:
 *    server public key || IUT private key || IUT public key || shared_secret
 *
 *  operation_result = CAVP_OPER_RES_KAS_VERIF_PASS or CAVP_OPER_RES_KAS_VERIF_FAIL
 */

#define SAB_HSM_ACVP_FUNCTION_KAS_KDF_VAL         (0x000C)
/*
 * KAS-KDF for VAL mode:
 *  - session_handle = session handle
 *  - service_handle = Unused
 *  - cavp_function = SAB_HSM_ACVP_FUNCTION_KAS_KDF_VAL
 *  - key_id = <unused>
 *  - value1 = dkm size
 *  - value2 = z size
 *  - input_address = see format below
 *  - output_address = <unused>
 *  - params_address = <unused>
 *  - input_size = variable
 *  - output_size = 0
 *  - params_size = 0
 *
 *  input buffer format:
 *    z || dkm || uPartyInfo || vPartyInfo
 *
 *  operation_result = CAVP_OPER_RES_KAS_VERIF_PASS or CAVP_OPER_RES_KAS_VERIF_FAIL
 */

#define SCU_DEVICE_PATH	"/dev/seco_mu1_ch2"

#define SECO_MU_IOCTL			0x0A /* like MISC_MAJOR. */

struct seco_mu_ioctl_signed_message {
	uint8_t *message;
	uint32_t msg_size;
	uint32_t error_code;
};

#define SECO_MU_IOCTL_SIGNED_MESSAGE	_IOWR(SECO_MU_IOCTL, 0x05, \
			struct seco_mu_ioctl_signed_message)

uint32_t test_hsm_cavp_support(hsm_test_struct_t *testCtx, FILE *fp);
uint32_t test_hsm_cavp_support_mct(hsm_test_struct_t *testCtx, FILE *fp);

#endif // __test_hsm_cavp_support_H__
