// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2019-2023 NXP
 */


#ifndef SAB_MSG_H
#define SAB_MSG_H

#include <stdint.h>
#include <plat_sab_msg_def.h>

#define MESSAGING_VERSION_6                     0x06u
#define MESSAGING_VERSION_7                     0x07u

#define V2X_SV0_API_VER                         0x02u

#define V2X_SV1_API_VER                         0x02u

#define V2X_SHE_API_VER                         0x02u

#define V2X_SG0_API_VER                         0x02u

#define V2X_SG1_API_VER                         0x02u

#define SAB_SESSION_OPEN_REQ                    0x10u
#define SAB_SESSION_CLOSE_REQ                   0x11u
#define SAB_SHARED_BUF_REQ                      0x12u
#define SAB_PUB_KEY_RECONSTRUCTION_REQ          0x13u
#define SAB_PUB_KEY_DECOMPRESSION_REQ           0x14u
#define SAB_ECIES_ENC_REQ                       0x15u
#define SAB_GET_INFO_REQ                        0x16u

#define SAB_RNG_OPEN_REQ                        0x20u
#define SAB_RNG_CLOSE_REQ                       0x21u

/* For debug s400, dump messsage
 * cmd id = 0x21, but version is 0x6
 */
#define ROM_DEBUG_DUMP_REQ                      0x21u
#define ROM_DEBUG_DUMP_MSG_SZ                   0x01u

#ifndef SAB_RNG_GET_RANDOM
#define SAB_RNG_GET_RANDOM                      0xCDu
#endif
#define SAB_RNG_EXTEND_SEED                     0x23u

#define SAB_KEY_STORE_OPEN_REQ                  0x30u
#define SAB_KEY_STORE_CLOSE_REQ                 0x31u
#define SAB_PUB_KEY_RECOVERY_REQ                0x32u
#define SAB_KEY_STORE_REPROV_EN_REQ             0x3Fu

#define SAB_KEY_MANAGEMENT_OPEN_REQ             0x40u
#define SAB_KEY_MANAGEMENT_CLOSE_REQ            0x41u
#define SAB_KEY_GENERATE_REQ                    0x42u
#define SAB_MANAGE_KEY_REQ                      0x43u
#define SAB_BUT_KEY_EXP_REQ                     0x44u
#define SAB_MANAGE_KEY_GROUP_REQ                0x45u
#define SAB_ROOT_KEK_EXPORT_REQ                 0x46u
#define SAB_KEY_EXCHANGE_REQ                    0x47u
#define SAB_TLS_FINISH_REQ                      0x48u
#define SAB_KEY_GENERATE_EXT_REQ                0x49u
#define SAB_MANAGE_KEY_EXT_REQ                  0x4au
#define SAB_IMPORT_KEY_EXT_REQ                  0x4au
#define SAB_ST_BUT_KEY_EXP_REQ                  0x4bu
#define SAB_GET_KEY_ATTR_REQ                    0x4Cu
#define SAB_DELETE_KEY_REQ                      0x4Eu
#define SAB_IMPORT_KEY_REQ                      0x4Fu

#define SAB_MAC_OPEN_REQ                        0x50u
#define SAB_MAC_CLOSE_REQ                       0x51u
#define SAB_MAC_ONE_GO_REQ                      0x52u

#define SAB_CIPHER_OPEN_REQ                     0x60u
#define SAB_CIPHER_CLOSE_REQ                    0x61u
#define SAB_CIPHER_ONE_GO_REQ                   0x62u
#define SAB_CIPHER_ECIES_DECRYPT_REQ            0x63u
#define SAB_AUTH_ENC_REQ                        0x64u

#define SAB_SIGNATURE_GENERATION_OPEN_REQ       0x70u
#define SAB_SIGNATURE_GENERATION_CLOSE_REQ      0x71u
#define SAB_SIGNATURE_GENERATE_REQ              0x72u
#define SAB_SIGNATURE_PREPARE_REQ               0x73u
#define SAB_PUB_KEY_ATTEST_REQ                  0x74u

#define SAB_SIGNATURE_VERIFICATION_OPEN_REQ     0x80u
#define SAB_SIGNATURE_VERIFICATION_CLOSE_REQ    0x81u
#define SAB_SIGNATURE_VERIFY_REQ                0x82u
#define SAB_IMPORT_PUB_KEY                      0x83u

#define SAB_HASH_OPEN_REQ                       0x90u
#define SAB_HASH_CLOSE_REQ                      0x91u
#ifndef SAB_HASH_ONE_GO_REQ
#define SAB_HASH_ONE_GO_REQ                     0xCCu
#endif

#define SAB_DATA_STORAGE_OPEN_REQ               0xA0u
#define SAB_DATA_STORAGE_CLOSE_REQ              0xA1u
#define SAB_DATA_STORAGE_REQ                    0xA2u
#define SAB_ENC_DATA_STORAGE_REQ                0xA3u

#define SAB_SM2_GET_Z_REQ                       0xB0U
#define SAB_SM2_ECES_ENC_REQ                    0xB1U
#define SAB_SM2_ECES_DEC_OPEN_REQ               0xB2U
#define SAB_SM2_ECES_DEC_CLOSE_REQ              0xB3U
#define SAB_SM2_ECES_DEC_REQ                    0xB4U

#define SAB_KEY_GENERIC_CRYPTO_SRV_OPEN_REQ     0xC0U
#define SAB_KEY_GENERIC_CRYPTO_SRV_CLOSE_REQ    0xC1U
#define SAB_KEY_GENERIC_CRYPTO_SRV_REQ          0xC2U
#define SAB_GC_ACRYPTO_REQ                      0xCAu
#define SAB_GC_AKEY_GEN_REQ                     0xCBu

#define ROM_DEV_FWD_LC_UPDATE                   0x95
#define ROM_DEV_RET_LC_UPDATE                   0xA0
#define ROM_DEV_GETINFO_REQ                     0xDA
#define ROM_DEV_ATTEST_REQ                      0xDB

/* FW: Maximum number of words without crc in a command */
#define SAB_STORAGE_NB_WORDS_MAX_WO_CRC         4u

#define SAB_STORAGE_OPEN_REQ                    0xE0u
#define SAB_STORAGE_CLOSE_REQ                   0xE1u
#define SAB_STORAGE_MASTER_IMPORT_REQ           0xE2u
#define SAB_STORAGE_MASTER_EXPORT_REQ           0xE3u
#define SAB_STORAGE_EXPORT_FINISH_REQ           0xE4u
#define SAB_STORAGE_CHUNK_EXPORT_REQ            0xE5u
#define SAB_STORAGE_CHUNK_GET_REQ               0xE6u
#define SAB_STORAGE_CHUNK_GET_DONE_REQ          0xE7u
#define SAB_STORAGE_KEY_DB_REQ                  0xE8u
#define SAB_RCVMSG_START_ID                     SAB_STORAGE_OPEN_REQ
#define SAB_STORAGE_NVM_LAST_CMD                (SAB_STORAGE_KEY_DB_REQ + 1)

#define SAB_RCVMSG_MAX_ID                       (SAB_STORAGE_KEY_DB_REQ \
							- SAB_RCVMSG_START_ID)

#define SAB_SHE_UTILS_OPEN                      0xF0u
#define SAB_SHE_UTILS_CLOSE                     0xF1u
#define SAB_SHE_KEY_UPDATE                      0xF2u
#define SAB_SHE_PLAIN_KEY_UPDATE                0xF3u
#define SAB_SHE_PLAIN_KEY_EXPORT                0xF4u
#define SAB_SHE_GET_ID                          0xF5u
#define SAB_SHE_GET_STATUS                      0xF6u
#define SAB_FAST_MAC_REQ                        0xF7u
#define SAB_SHE_KEY_UPDATE_EXT                  0xF8u
#define SAB_SHE_FAST_MAC_MUBUFF_REQ		0xF9u

#define SAB_MSG_MAX_ID				0xFFu

#define GET_STATUS_CODE(rsp_code)               ((uint8_t)((rsp_code) & 0xFFu))
#define GET_RATING_CODE(rsp_code)               ((uint8_t)\
						(((rsp_code) >> 8) & 0xFFu))

/* Status code definition */
#define SAB_FAILURE_STATUS                      0x29u
#define SAB_CRC_FAILURE_STATUS                  0xB929u
#define SAB_INVALID_MSG_STATUS                  0xF429u
#define SAB_ENGN_PASS                           0x0u
#define SAB_ENGN_FAIL                           0x1u

/* 4 word is must for adding CRC. */
#define NB_BYTES_CRC_MANDATE                    (0x10u)

/* Rating code definition */
#define SAB_NO_MESSAGE_RATING                   (0x00u)
#define SAB_INVALID_MESSAGE_RATING              (0x01u)
#define SAB_INVALID_ADDRESS_RATING              (0x02u)
#define SAB_UNKNOWN_ID_RATING                   (0x03u)
#define SAB_INVALID_PARAM_RATING                (0x04u)
#define SAB_NVM_ERROR_RATING                    (0x05u)
#define SAB_OUT_OF_MEMORY_RATING                (0x06u)
#define SAB_UNKNOWN_HANDLE_RATING               (0x07u)
#define SAB_UNKNOWN_KEY_STORE_RATING            (0x08u)
#define SAB_KEY_STORE_AUTH_RATING               (0x09u)
#define SAB_KEY_STORAGE_ERROR_RATING            (0x0Au)
#define SAB_ID_CONFLICT_RATING                  (0x0Bu)
#define SAB_RNG_NOT_STARTED_RATING              (0x0Cu)
#define SAB_CMD_NOT_SUPPORTED_RATING            (0x0Du)
#define SAB_INVALID_LIFECYCLE_RATING            (0x0Eu)
#define SAB_KEY_STORE_CONFLICT_RATING           (0x0Fu)
#define SAB_KEY_STORE_COUNTER_RATING            (0x10u)
#define SAB_FEATURE_NOT_SUPPORTED_RATING        (0x11u)
#define SAB_SELF_TEST_FAILURE_RATING            (0x12u)
#define SAB_NOT_READY_RATING                    (0x13u)
#define SAB_FEATURE_DISABLED_RATING             (0x14u)
#define SAB_SIGNED_MSG_INVALID_RATING           (0x18u)
#define SAB_OUT_OF_MEM_TO_STORE_KEY_IN_KEYGRP   (0x19u)
#define SAB_NOT_POSSIBLE_RETRIEVE_CHUNK         (0x1Au)
#define SAB_KEY_NOT_SUPPORTED_RATING            (0x1Bu)
#define SAB_TRYING_TO_DEL_PERM_KEY              (0x1Cu)
#define SAB_OUT_LEN_TOO_SHORT_RATING            (0x1Du)
#define SAB_DATA_ALREADY_RETRIEVED_RATING       (0x1Fu)
#define SAB_CRC_CHECK_FAIL_RATING               (0xB9u)
#define SAB_INVALID_LIFECYCLE_OP_RATING         (0xF2u)

/* SHE specific rating */
#define SAB_SHE_SEQUENCE_ERROR_RATING           (0xD1u)     /**< Invalid sequence of commands. */
#define SAB_SHE_KEY_NOT_AVAILABLE_RATING        (0xD2u)     /**< Key is locked. */
#define SAB_SHE_KEY_INVALID_RATING              (0xD3u)     /**< Key not allowed for the given operation. */
#define SAB_SHE_KEY_EMPTY_RATING                (0xD4u)     /**< Key has not beed initialized yet. */
#define SAB_SHE_NO_SECURE_BOOT_RATING           (0xD5u)     /**< Conditions for a secure boot process are not met. */
#define SAB_SHE_KEY_WRITE_PROTECTED_RATING      (0xD6u)     /**< Memory slot for this key has been write-protected. */
#define SAB_SHE_KEY_UPDATE_ERROR_RATING         (0xD7u)     /**< Key update did not succeed due to errors in verification of the messages. */
#define SAB_SHE_RNG_SEED_RATING                 (0xD8u)     /*< The seed has not been initialized. */
#define SAB_SHE_NO_DEBUGGING_RATING             (0xD9u)     /**< Internal debugging is not possible. */
#define SAB_SHE_BUSY_RATING                     (0xDAu)     /**< A function of SHE is called while another function is still processing. */
#define SAB_SHE_MEMORY_FAILURE_RATING           (0xDBu)     /**< Memory error (e.g. flipped bits) */
#define SAB_SHE_GENERAL_ERROR_RATING            (0xDCu)     /**< Error not covered by other codes occured. */

#define SAB_READ_FAILURE_RATING                 (0xFEu)
#define SAB_FATAL_FAILURE_RATING                (0xFFu)

/**
 * Helps in returning PLAT errors info in addition to
 * library error code
 */
#define SAB_LIB_ERR_PLAT_SHIFT                  (0x8u)

/**
 * SAB library level ratings
 */
#define SAB_LIB_SUCCESS                         (0xE000u)
#define SAB_LIB_INVALID_MSG_HANDLER             (0xE300u)
#define SAB_LIB_CMD_MSG_PREP_FAIL               (0xE400u)
#define SAB_LIB_CMD_RSP_TRANSACT_FAIL           (0xE500u)
#define SAB_LIB_RSP_PROC_FAIL                   (0xE600u)
#define SAB_LIB_CRC_FAIL                        (0xE700u)
#define SAB_LIB_ERROR                           (0xEF00u)

/**
 * Following Library error codes need to be treated same as SAB errors
 */
#define SAB_LIB_CMD_UNSUPPORTED \
	(SAB_CMD_NOT_SUPPORTED_RATING << SAB_LIB_ERR_PLAT_SHIFT)
#define SAB_LIB_CMD_INVALID \
	(SAB_INVALID_MESSAGE_RATING << SAB_LIB_ERR_PLAT_SHIFT)
#define SAB_LIB_SHE_CANCEL_ERROR \
	(SAB_SHE_GENERAL_ERROR_RATING << SAB_LIB_ERR_PLAT_SHIFT)

/**
 * Engine macros for setting and comparing library error path,
 *	-SEND MSG PATH for Prepare CMD MSG, adding CRC etc.
 *	-RECEIVE RESP PATH for Parse RESP, Validate CRC etc.
 */
#define ENGN_SEND_CMD_PATH_FLAG                 (0x0u)
#define ENGN_RCV_RESP_PATH_FLAG                 (0x00010000u)

/**
 * Macros used during setting and parsing Library error status,
 * Path of the error received, and Plat error
 */
#define LIB_ERR_PATH_MASK                       (0x00FF0000u)
#define LIB_ERR_STATUS_MASK                     (0x0000FF00u)
#define LIB_ERR_PLAT_MASK                       (0x000000FF)
#define LIB_ERR_PATH_SHIFT                      (0x10u)
#define LIB_ERR_STATUS_SHIFT                    (0x8u)
#define LIB_ERR_PLAT_SHIFT                      (0x0u)

/**
 * Set library error path(direction), library platform error
 * in the Library error code
 */
#define RCVMSG_ENGN_ERR(lib_err_status) \
		(ENGN_RCV_RESP_PATH_FLAG | \
		 (lib_err_status) | \
		 PLAT_SUCCESS)
#define SENDMSG_ENGN_ERR(lib_err_status) \
		(ENGN_SEND_CMD_PATH_FLAG | \
		 (lib_err_status) | \
		 PLAT_SUCCESS)

/**
 * Parse Error path(direction), Library error status, Platform error
 * from library error code.
 */
#define PARSE_LIB_ERR_PATH(lib_err) \
		((lib_err) & LIB_ERR_PATH_MASK)
#define PARSE_LIB_ERR_STATUS(lib_err) \
		((lib_err) & LIB_ERR_STATUS_MASK)
#define PARSE_LIB_ERR_PLAT(lib_err) \
		((lib_err) & LIB_ERR_PLAT_MASK)

/**
 * For ease of enhancements in SAB APIs error code
 */
#define SAB_LIB_STATUS(sab_lib_err)             (sab_lib_err)

struct sab_mu_hdr {
    uint8_t ver;
    uint8_t size;
    uint8_t command;
    uint8_t tag;
};

#endif
