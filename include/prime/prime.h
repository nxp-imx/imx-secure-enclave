// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef PRIME_H
#define PRIME_H

/**
 * @defgroup prime_core PRIME Cryptographic Engine
 * @brief PRIME (Performance-optimized Real-time Integrated Message Encryption) API
 *
 * This is the main interface for PRIME cryptographic operations providing:
 * - AES cipher operations (CBC, ECB, CTR)
 * - AEAD operations (GCM, CCM)
 * - HMAC and SHA hash operations
 * - Asynchronous operation processing
 * @{
 */

#include <stddef.h>

#include "internal/prime_handle.h"
#include "internal/prime_hmac.h"
#include "internal/prime_aes.h"
#include "internal/prime_service.h"

/**
 * @brief Cryptographic operation types
 *
 * Enumeration of supported cryptographic operation types that can be
 * processed by the PRIME engine.
 */
enum crypto_op_type {
	CRYPTO_OP_TYPE_NONE,
	//!< No operation or uninitialized
	CRYPTO_OP_TYPE_AES,
	//!< AES cipher operation (CBC, ECB, CTR)
	CRYPTO_OP_TYPE_AEAD,
	//!< AEAD operation (GCM, CCM)
	CRYPTO_OP_TYPE_HMAC,
	//!< HMAC or SHA hash operation
	CRYPTO_OP_TYPE_HASH,
	//!< Hash one go operation (standalone hash, no key required)
	CRYPTO_OP_TYPE_MAX,
	//!< Maximum operation type (boundary marker)
};

/**
 * @brief Status of cryptographic operation
 *
 * Indicates the current state of a cryptographic operation in the
 * processing pipeline.
 */
enum crypto_op_status {
	CRYPTO_OP_COMPLETED,
	//!< Operation completed, dequeue done after receiving interrupt
	CRYPTO_OP_SUBMITTED,
	//!< Operation submitted, enqueue done
	CRYPTO_OP_FIFO_FULL,
	//!< Operation failed, FIFO is full
	CRYPTO_OP_INVALID_HANDLE,
	//!< Operation failed, invalid handle
	CRYPTO_OP_INVALID_ALGO,
	//!< Operation failed, invalid cryptographic algorithm
	CRYPTO_OP_MSG_BUILD_FAILED,
	//!< Failed to build MU message
};

/**
 * @brief Status buffer structure updated by firmware
 *
 * This structure contains the operation status information written
 * by the firmware upon completion of a cryptographic operation.
 */
typedef struct status_buf {
	uint8_t status_code;
	//!< Status code (0xD6 = success, other values indicate errors)
	uint8_t error_info;
	//!< Additional error information for debugging
	uint16_t reserved;
	//!< Reserved for future use
} status_buf_t;

/**
 * @brief Cryptographic operation status tracking
 *
 * Contains physical and virtual addresses of the status buffer
 * used for tracking operation completion.
 */
struct crypto_status {
	status_buf_t *phys_addr;
	//!< Physical address of status buffer (for hardware access)
	status_buf_t *virt_addr;
	//!< Virtual address of status buffer (for software access)
};

/**
 * @brief PRIME cryptographic operation descriptor
 *
 * Main structure describing a cryptographic operation to be processed
 * by the PRIME engine. Contains source/destination buffers, operation
 * type, and type-specific parameters.
 */
typedef struct prime_crypto_op {
	struct buf src;
	//!< Source data buffer (input for encryption/hashing)
	struct buf dst;
	//!< Destination data buffer (output for encryption/hashing)
	uint32_t req_id;
	//!< Request identifier for tracking (to be deleted from user interface)
	struct crypto_status crypto_status;
	//!< Status tracking structure for operation completion
	enum crypto_op_status op_status;
	//!< Current status of the operation
	enum crypto_op_type op_type;
	//!< Type of cryptographic operation to perform
	union {
		struct aes_op_params op_aes_args;
		//!< AES cipher operation parameters
		struct aead_op_params op_aead_args;
		//!< AEAD operation parameters
		struct mac_op_params op_mac_args;
		//!< HMAC/MAC operation parameters
		struct hash_one_go_op_params op_hash_args;
		//!< Hash one go operation parameters
	};
} crypto_op_args_t;

/**
 * @brief Process cryptographic operations
 *
 * Submit one or more cryptographic operations to the PRIME engine for
 * processing. Operations are queued and processed asynchronously by
 * the hardware accelerator.
 *
 * @param[in] service_hdl Handle to the PRIME service session
 * @param[in,out] ops Array of pointers to cryptographic operation descriptors
 * @param[in] nb_ops Number of operations in the array
 *
 * @return Number of operations successfully submitted (>= 0)
 * @return Negative value on error
 */
int prime_process_ops(prime_hdl_t service_hdl,
		      crypto_op_args_t **ops,
		      uint32_t nb_ops);

/** @} */ /* end of prime_core group */

#endif
