// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef KEY_STORE_H
#define KEY_STORE_H

#include <stdint.h>

/**
 * Structure specifying the open key store service member arguments
 */
typedef struct {
	uint32_t key_store_hdl;
	//!< handle identifying the key store service flow
	uint32_t key_store_identifier;
	//!< user defined id identifying the key store.
	//!< Only one key store service can be opened on a given key_store_identifier.
	uint32_t authentication_nonce;
	//!< user defined nonce used as authentication proof for accessing the
	//!< key store.
	uint8_t flags;
	//!< bitmap specifying the services properties.
#ifndef PSA_COMPLIANT
	uint16_t max_updates_number;
	//!< maximum number of updates authorized for the key store.
	//!< - Valid only for create operation.\n
	//!< - This parameter has the goal to limit the occupation of the
	//!< monotonic counter used as anti-rollback protection.\n
	//!< -  If the maximum number of updates is reached, HSM still allows
	//!< key store updates but without updating the monotonic counter giving
	//!< the opportunity for rollback attacks.
	uint8_t min_mac_length;
	//!< it corresponds to the minimum mac length (in bits) accepted
	//!< to perform MAC verification operations.\n
	//!< Only used upon key store creation when KEY_STORE_FLAGS_SET_MAC_LEN
	//!< bit is set.\n
	//!< It is effective only for MAC verification operations with the
	//!< mac length expressed in bits.\n
	//!< It can be used to replace the default value (32 bits).\n
	//!< It impacts all MAC algorithms and all key lengths.\n
	//!< It must be different from 0.\n
	//!< When in FIPS approved mode values < 32 bits are not allowed.\n
	//!< Only used on devices implementing SECO FW.
#endif
	uint8_t *signed_message;
	//!< pointer to signed_message to be sent only in case of
	//!< key store re-provisioning.
	uint16_t signed_msg_size;
	//!< size of the signed_message to be sent only in case of
	//!< key store re-provisioning.
} open_svc_key_store_args_t;

#endif
