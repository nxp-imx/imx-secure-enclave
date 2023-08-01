// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_DATA_STORAGE_H
#define HSM_DATA_STORAGE_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_common_def.h"

/**
 *  @defgroup group13 Data storage
 * @{
 */

/**
 * Bitmap specifying the data storage open service supported properties
 */
typedef uint8_t hsm_svc_data_storage_flags_t;

/**
 * Structure specifying the data storage open service member arguments
 */
typedef struct {
	hsm_hdl_t data_storage_handle;        //!< data storage handle.
	hsm_svc_data_storage_flags_t flags;   //!< bitmap specifying the services properties.
	uint8_t reserved[3];
} open_svc_data_storage_args_t;

/**
 * Open a data storage service flow\n
 * User must open this service flow in order to store/retrieve generic data in/from the HSM.
 *
 * \param key_store_hdl handle identifying the key store service flow.
 * \param args pointer to the structure containing the function arguments.

 * \param data_storage_hdl pointer to where the data storage service flow handle must be written.
 *
 * \return error_code error code.
 */
hsm_err_t hsm_open_data_storage_service(hsm_hdl_t key_store_hdl,
					open_svc_data_storage_args_t *args,
					hsm_hdl_t *data_storage_hdl);

/**
 * Bitmap specifying the data storage operation supported attributes
 */
typedef uint8_t hsm_op_data_storage_flags_t;

/**
 * Structure detailing the data storage operation member arguments
 */
typedef struct {
	uint8_t *data;
	//!< pointer to the data. In case of store request,
	//!< it will be the input data to store. In case of retrieve,
	//!< it will be the pointer where to load data.
	uint32_t data_size;
	//!< length in bytes of the data
	uint32_t data_id;
	//!< id of the data
	hsm_op_data_storage_flags_t flags;
	//!< flags bitmap specifying the operation attributes.
	hsm_svc_data_storage_flags_t svc_flags;
	//!< bitmap specifying the services properties.
#ifdef PSA_COMPLIANT
	/**
	 * In case RETRIEVE, if the data retrieved is in TLV format
	 * which was stored by Encrypted Data Storage API. The TLV
	 * format data will be decoded to fill the following fields.
	 */
	uint16_t uuid_len;
	//!< Device UUID length in bytes
	uint8_t *uuid;
	//!< Device UUID
	uint16_t iv_len;
	//!< IV length in bytes, if needed, otherwise 0
	uint8_t *iv;
	//!< IV buffer, if needed
	uint32_t ciphertext_len;
	//!< encrypted text length in bytes
	uint8_t *ciphertext;
	//!< encrypted text buffer
	uint32_t payload_len;
	//!< payload length in bytes
	uint8_t *payload;
	//!< payload data buffer to verify signature
	uint16_t signature_len;
	//!< signature length in bytes
	uint8_t *signature;
	//!< signature buffer
	uint32_t exp_output_size;
	//!< expected output buffer size in bytes, valid in case of HSM_OUT_TOO_SMALL
	//!< (0x1D) error code
#endif
} op_data_storage_args_t;

/**
 * Store or retrieve generic data identified by a data_id. \n
 *
 * \param data_storage_hdl handle identifying the data storage service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_data_storage(hsm_hdl_t data_storage_hdl, op_data_storage_args_t *args);
#define HSM_OP_DATA_STORAGE_FLAGS_EL2GO    ((hsm_op_data_storage_flags_t)(1u << 0))
#define HSM_OP_DATA_STORAGE_FLAGS_DEFAULT  ((hsm_op_data_storage_flags_t)(0u << 0))
//!< Store data.
#define HSM_OP_DATA_STORAGE_FLAGS_STORE    ((hsm_op_data_storage_flags_t)(1u << 1))
//!< Retrieve data.
#define HSM_OP_DATA_STORAGE_FLAGS_RETRIEVE ((hsm_op_data_storage_flags_t)(0u << 1))

/**
 * Encrypted Data TLV Tags
 */
#define ENC_DATA_TLV_DEV_UUID_TAG   0x41u
#define ENC_DATA_TLV_IV_TAG         0x45u
#define ENC_DATA_TLV_ENC_DATA_TAG   0x46u
#define ENC_DATA_TLV_SIGN_TAG       0x5Eu

/**
 * Encrypted Data TLV Tags lengths
 */
#define ENC_DATA_TLV_DEV_UUID_TAG_LEN   0x01u
#define ENC_DATA_TLV_IV_TAG_LEN         0x01u
#define ENC_DATA_TLV_ENC_DATA_TAG_LEN   0x01u
#define ENC_DATA_TLV_SIGN_TAG_LEN       0x01u

/**
 * Bitmap specifying the encrypted data storage operation supported attributes
 */
typedef uint16_t hsm_op_enc_data_storage_flags_t;
#define HSM_OP_ENC_DATA_STORAGE_FLAGS_RANDOM_IV \
	((hsm_op_enc_data_storage_flags_t)(1u << 0))
//!< internally generate random IV, if needed for operation.
#define HSM_OP_ENC_DATA_STORAGE_FLAGS_READ_ONCE \
	((hsm_op_enc_data_storage_flags_t)(1u << 1))
//!< read once, and delete data from NVM after retrieve.

typedef struct {
	uint32_t data_id;
	//!< id of the data
	uint8_t *data;
	//!< pointer to the data, to be encrypted and signed
	uint32_t data_size;
	//!< length in bytes of the data
	uint32_t enc_algo;
	//!< cipher algorithm to be used for encryption of data
	uint32_t enc_key_id;
	//!< identifier of the key to be used for encryption
	uint32_t sign_algo;
	//!< signature algorithm to be used for signing the data
	uint32_t sign_key_id;
	//!< identifier of the key to be used for signing
	uint8_t *iv;
	//!< pointer to the IV buffer
	uint16_t iv_size;
	//!< IV size in bytes
	hsm_op_enc_data_storage_flags_t flags;
	//!< bitmap specifying the operation attributes
	hsm_svc_data_storage_flags_t svc_flags;
	//!< bitmap specifying the service attributes.
	uint16_t lifecycle;
	//!< bitmask of device lifecycle, in which the data can be retrieved
	uint32_t out_data_size;
	//!< size (bytes) of the signed TLV stored, received with API resp
} op_enc_data_storage_args_t;

/**
 * Store encrypted and signed data in the NVM. \n
 *
 * \param data_storage_hdl handle identifying the data storage service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_enc_data_storage(hsm_hdl_t data_storage_hdl,
			       op_enc_data_storage_args_t *args);
/**
 * Decode and populate the data storage op args for Encrypted Data TLV fields
 *
 * \param args pointer to the structure containing Retrieved Encrypted Data TLV
 *  buffer and to be populated with decoded data from TLV.
 *
 * \return error code 0 for success
 */
uint8_t decode_enc_data_tlv(op_data_storage_args_t *args);

/**
 * Terminate a previously opened data storage service flow
 *
 * \param data_storage_hdl handle identifying the data storage service flow.
 *
 * \return error code
 */
hsm_err_t hsm_close_data_storage_service(hsm_hdl_t data_storage_hdl);

/** @} end of data storage service flow */
#endif
