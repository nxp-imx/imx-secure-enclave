// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef HSM_GEN_ELE_KEY_BLOB_H
#define HSM_GEN_ELE_KEY_BLOB_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"

/**
 *  @defgroup group40 GEN-ELE-KEY-BLOB
 * @{
 */

#define GEN_ELE_KEY_BLOB_FORMAT_TAG	0x81
#define GEN_ELE_KEY_BLOB_FORMAT_VERS	0x00

typedef uint8_t hsm_op_gen_ele_key_blob_flags_t;

#define HSM_OP_GEN_ELE_KEY_BLOB_FLAG_BLOB_TYPE_DEK \
			((hsm_op_gen_ele_key_blob_flags_t)(1u << 0))
//!< Use flag for blob type as DEK.
#define HSM_OP_GEN_ELE_KEY_BLOB_FLAG_BLOB_TYPE_OTFAD_CONF \
			((hsm_op_gen_ele_key_blob_flags_t)(1u << 1))
//!< Use flag for blob type for OTFAD configuration.

/**
 * Enum describing the encryption algos used for ELE key blob generation.
 */
typedef enum {
	HSM_OP_GEN_ELE_KEY_BLOB_ALGO_AES_CBC = 0x03,
	HSM_OP_GEN_ELE_KEY_BLOB_ALGO_AES_CTR = 0x04,
	HSM_OP_GEN_ELE_KEY_BLOB_ALGO_SM4_CBC = 0x2b,
	HSM_OP_GEN_ELE_KEY_BLOB_ALGO_AES_XTS = 0x37,
} hsm_op_gen_ele_key_blob_algo_t;

/**
 * Structure specifying the OTFAD Key configuration format.
 */
typedef struct {
	uint8_t aes_key[16];
	//!< AES key to use for OTFAD Key blob.
	uint64_t aes_key_counter;
	//!< AES key counter for OTFAD Key blob.
	uint32_t key_start_addr;
	//!< AES key buffer start address.
	uint32_t key_end_addr;
	//!< AES key buffer end address.
	uint32_t reserved;
	//!< Reserved.
	uint32_t crc;
	//!< CRC
} op_gen_ele_key_blob_otfad_key_conf_t;

/* OP_GEN_ELE_KEY_BLOB_PAYLOAD_OTFAD_SZ must be equal to
 * sizeof(op_gen_ele_key_blob_otfad_key_conf_t)
 */
#define OP_GEN_ELE_KEY_BLOB_PAYLOAD_OTFAD_SZ		0x28
#define OP_GEN_ELE_KEY_BLOB_PAYLOAD_DEK_AES128_CBC_SZ	0x10
#define OP_GEN_ELE_KEY_BLOB_PAYLOAD_DEK_AES192_CBC_SZ	0x18
#define OP_GEN_ELE_KEY_BLOB_PAYLOAD_DEK_AES256_CBC_SZ	0x20
#define OP_GEN_ELE_KEY_BLOB_PAYLOAD_DEK_SM4_CBC_SZ	0x10

/**
 * Structure specifying the gen-ele-key-blob-format.
 */
typedef struct {
	uint8_t vers;
	//!< Hard-coded as GEN_ELE_KEY_BLOB_FORMAT_VERS.
	uint16_t length;
	//!< Total length in bytes of the header and its payload..
	uint8_t tag;
	//!< Tag identifier. Hard-coded as GEN_ELE_KEY_BLOB_FORMAT_TAG.
	hsm_op_gen_ele_key_blob_flags_t flag;
	//!< Usage flag to specify the type of ELE key blob to generate.
	uint8_t raw_data_sz;
	//!< Size of the raw data (without the blob overhead and the header).
	//!< Depends on flag used.
	uint8_t algo;
	//!< Symmetric cipher algorithm to use to generte the blob.
	uint8_t resrv;
	//!< Reserved.
	uint8_t payload[OP_GEN_ELE_KEY_BLOB_PAYLOAD_OTFAD_SZ];
	//!< Payload as per flag and algo.
} op_gen_ele_key_blob_format_t;

/**
 * Structure specifying the gen-ele-key-blob request.
 */
typedef struct {
	uint32_t key_id;
	//!< Depends on the blob type: Non-OTFAD or OTFAD.
	//!< For Non-OTFAD:
	//!< Identifier of the input key (defined by the user).
	//!< The same value has to be provided again when decrypting the generated blob.
	//!<
	//!< For OTFAD:
	//!< Byte 0: Index of the OTFAD key struct (0 .. 3).
	//!<         Important when the key scrambling is enabled.
	//!< Byte 1: 0x1: FlexSPI 1, 0x2: FlexSPI 2
	//!< Byte 2-3: Reserved.
	uint8_t *load_addr;
	//!< Address where the input data can be loaded from. Must be 64 bit aligned.
	//!< Input data consists in the blob header as defined by the Blob format,
	//!< filled with relevant info and followed by plaintext data to be encrypted.
	uint32_t load_addr_sz;
	//!< Size of data to be loaded.
	uint8_t *store_addr;
	//!< Address space, where user input to blob-key derivation context, can be found.
	uint32_t store_addr_sz;
	//!< Size of data to be stored.
	uint16_t max_export_sz;
	//!< Maximum memory available in bytes at the provided address.
	//!< (Note that the blob needs 48 bytes more than the plaintext key.)
} op_gen_ele_key_blob_msg_args_t;

/**
 * This API enables:
 * - Generating the ELE Key-blob based on the provided ELE-Key-Blob-Format
 *   at args->load_addr.
 * - Generated ELE Key-blob will be stored at args->store_addr.
 *
 * \param session_hdl handle identifying the session handle.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_gen_ele_key_blob(hsm_hdl_t session_hdl,
			       op_gen_ele_key_blob_msg_args_t *args);

/** @} end of gen-ele-key-blob operation */
#endif //HSM_GEN_ELE_KEY_BLOB_H
