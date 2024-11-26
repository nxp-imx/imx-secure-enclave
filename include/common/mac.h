// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef MAC_H
#define MAC_H

#include <stdint.h>
#include "utils.h"

/**
 *  @defgroup group20 Mac
 * @{
 */
/**
 * Structure describing the mac open service member agruments
 */
typedef struct {
#ifndef PSA_COMPLIANT
	uint8_t flags;
	//!< bitmap specifying the services properties.
#endif
	uint32_t mac_serv_hdl;
	//!< indicates the mac handle.
} open_svc_mac_args_t;

/**
 * Bit indicating mac verify operation
 */
#define MAC_OP_FLAGS_MAC_VERIFICATION	0u

/**
 * Bit indicating mac generate operation
 */
#define MAC_OP_FLAGS_MAC_GENERATION		BIT(0)

#ifndef PSA_COMPLIANT
/**
 * Bit indicating mac generate operation
 */
#define MAC_OP_FLAGS_MAC_LENGTH_IN_BITS		BIT(1)
#endif

#ifdef PSA_COMPLIANT
/**
 * Bit indicating the PLAINTEXT key user input
 */
#define MAC_OP_FLAGS_PLAINTEXT_KEY		BIT(3)
#endif

/**
 * Structure describing the mac operation member agruments
 */
typedef struct {
	uint32_t key_identifier;
	//!< identifier of the key to be used for the operation
#ifdef PSA_COMPLIANT
	//!< The flag for PLAINTEXT key must not be set.
	uint8_t *key;
	//!< pointer to the plaintext key buffer.
	//!< The flag for PLAINTEXT key must be set.
	//!< Only valid for INIT and ONE SHOT operations.
#endif
#ifdef PSA_COMPLIANT
	uint32_t algorithm;
	//!< algorithm to be used for the operation
	uint16_t flags;
	//!< bitmap specifying the operation attributes
#else
	uint8_t algorithm;
	//!< algorithm to be used for the operation
	uint8_t flags;
	//!< bitmap specifying the operation attributes
#endif
	uint8_t *payload;
	//!< pointer to the payload area
#ifdef PSA_COMPLIANT
	//!< Only valid for UPDATE DATA and ONE SHOT operations.
#endif
	uint8_t *mac;
	//!< pointer to the mac area
	//!<   - MAC generation: Output MAC value
	//!<   - MAC verification: Input MAC value to verify
#ifdef PSA_COMPLIANT
	//!< Only valid for FINALIZE, FINALIZE VERIFY and ONE SHOT operations.
#endif
	uint32_t payload_size;
	//!< length in bytes of the payload
#ifdef PSA_COMPLIANT
	//!< Only valid for UPDATE DATA and ONE SHOT operations.
#endif
	uint16_t mac_size;
	//!< length of the MAC.
#ifndef PSA_COMPLIANT
	//!< - Specified in bytes if MAC_OP_FLAGS_MAC_LENGTH_IN_BITS
	//!<   is clear.
	//!< - Specified in bits when MAC_OP_FLAGS_MAC_LENGTH_IN_BITS
	//!<   is set.
	//!<   Note:
	//!<   - When specified in bytes the mac size cannot be less than 4 bytes.
	//!<   - When specified in bits the mac size cannot be less than:
	//!<     -- the key specific min_mac_len setting if specified for this key
	//!<        when generated/injected; or
	//!<     -- the min_mac_length value if specified at the key store
	//!<        provisioning.
	//!<        (if a key specific setting was not specified at key
	//!<         generation/injection); or
	//!<     -- the default value (32 bit) if a minimum has not been specified
	//!<        using one of the above 2 methods.
#else
	//!< Only valid for FINALIZE, FINALIZE VERIFY and ONE SHOT operations.
	uint16_t key_type;
	//!< Key type. Only valid with PLAINTEXT flag.
	//!< Only valid with ONE SHOT or INIT operations.
	uint16_t key_size;
	//!< Key size in bytes. Only valid with PLAINTEXT flag.
	//!< Only valid with ONE SHOT or INIT operations.
	uint8_t *context;
	//!< Context buffer. Only valid with PLAINTEXT flag.
	uint16_t context_size;
	//!< Size in Bytes of context buffer. Only valid with PLAINTEXT flag.
#endif
	uint32_t verification_status;
	//!< mac verification status.
#ifdef PSA_COMPLIANT
	uint16_t exp_mac_size;
	//!< expected mac size for output, returned by FW in case the mac size
	//!<	 provided is less than the expected mac size calculated from MAC
	//!<	 algorithm.
	//!< Note: This field will be deprecated soon. exp_output_size to be
	//!< be used instead.
	uint16_t exp_output_size;
	//!< Expected output buffer size in bytes, valid in case of HSM_OUT_TOO_SMALL
	//!< (0x1D) error code.
	//!< In case of streaming operation, Expected context size in bytes if
	//!< operation failed with 0x1E.
#else
	uint8_t svc_flags;
	//!< bitmap specifying the services properties.
#endif
} op_mac_args_t;

/**
 * Structure describing the mac one go operation member agruments
 */
typedef op_mac_args_t op_mac_one_go_args_t;

/** @} end of mac service flow */
#endif
