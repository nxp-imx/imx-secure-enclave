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
	hsm_hdl_t data_storage_handle;
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
	//!< pointer to the data. In case of store request,
	//   it will be the input data to store. In case of retrieve,
	//   it will be the pointer where to load data.
	uint8_t *data;
	//!< length in bytes of the data
	uint32_t data_size;
	//!< id of the data
	uint32_t data_id;
	//!< bitmap specifying the services properties.
	hsm_svc_data_storage_flags_t flags;
	//!< flags bitmap specifying the operation attributes.
	hsm_op_data_storage_flags_t svc_flags;
#ifdef PSA_COMPLIANT
	//!< expected output buffer size in bytes, valid in case of HSM_OUT_TOO_SMALL
	//   (0x1D) error code
	uint32_t exp_output_size;
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
 * Terminate a previously opened data storage service flow
 *
 * \param data_storage_hdl handle identifying the data storage service flow.
 *
 * \return error code
 */
hsm_err_t hsm_close_data_storage_service(hsm_hdl_t data_storage_hdl);

/** @} end of data storage service flow */
#endif
