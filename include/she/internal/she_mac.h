// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024, 2026 NXP
 */

#ifndef SHE_MAC_H
#define SHE_MAC_H

#include "she_handle.h"
#include "she_utils.h"
#include "common/mac.h"

/**
 *  @defgroup group20 CMD_GENERATE_CMAC and CMD_VERIFY_CMAC
 * \ingroup group100
 * @{
 */

/**
 * Open a mac service flow on SHE V2X
 *
 * User can call this function only after having opened
 * a key store service flow.
 *
 * User must open this service in order to perform mac operation
 *
 * \param key_store_hdl handle identifying the key store service flow.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
she_err_t she_open_mac_service(she_hdl_t key_store_hdl,
			       open_svc_mac_args_t *args);

/**
 * Bitmap describing the mac verification status
 */
typedef uint32_t she_mac_verification_status_t;

/**
 * Bit indicating mac verification success status
 */
#define SHE_MAC_VERIFICATION_STATUS_SUCCESS \
				((she_mac_verification_status_t)(0x6C1AA1C6u))

/**
 * Bitmap describing the mac one go operation permitted algorithm
 */
typedef uint8_t she_op_mac_one_go_algo_t;

#define SHE_OP_MAC_ONE_GO_ALGO_CMAC \
				((she_op_mac_one_go_algo_t)(0x09u))

/**
 * Perform mac operation
 * User can call this function only after having opened a mac service flow
 *
 * For mac verification operations, the verified mac length can be specified in:
 * - Bits by setting the MAC_OP_FLAGS_MAC_LENGTH_IN_BITS flag,
 * - if this flag is clear then the mac_length is specified in bytes.
 *
 * For mac generation operations:
 * - mac length must be set in bytes, and
 * - MAC_OP_FLAGS_MAC_LENGTH_IN_BITS flag must be 0
 *
 * \param mac_hdl handle identifying the mac service flow.
 * \param args pointer to the structure containing the function arguments.
 * \param status pointer for storing the verification status.
 *
 * \return error code
 */
she_err_t she_mac_one_go(she_hdl_t mac_hdl, op_mac_one_go_args_t *args,
			 she_mac_verification_status_t *status);

/**
 * Terminate a previously opened mac service flow
 *
 * \param mac_hdl  pointer to handle identifying the mac service flow
 *                 to be closed.
 *
 * \return error code
 */
she_err_t she_close_mac_service(she_hdl_t mac_hdl);

/** @} end of mac service flow */
#endif
