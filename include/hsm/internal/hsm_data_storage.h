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

#ifndef HSM_DATA_STORAGE_H
#define HSM_DATA_STORAGE_H

#include "internal/hsm_handle.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_common_def.h"

/**
 *  @defgroup group13 Data storage
 * @{
 */

typedef uint8_t hsm_svc_data_storage_flags_t;
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

typedef uint8_t hsm_op_data_storage_flags_t;
typedef struct {
	//!< pointer to the data. In case of store request,
	//   it will be the input data to store. In case of retrieve,
	//   it will be the pointer where to load data.
	uint8_t *data;
	//!< length in bytes of the data
	uint32_t data_size;
	//!< id of the data
	uint16_t data_id;
	//!< bitmap specifying the services properties.
	hsm_svc_data_storage_flags_t flags;
	//!< flags bitmap specifying the operation attributes.
	hsm_op_data_storage_flags_t svc_flags;
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
#define HSM_OP_DATA_STORAGE_FLAGS_STORE    ((hsm_op_data_storage_flags_t)(1u << 0)) //!< Store data.
#define HSM_OP_DATA_STORAGE_FLAGS_RETRIEVE ((hsm_op_data_storage_flags_t)(0u << 0)) //!< Retrieve data.

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