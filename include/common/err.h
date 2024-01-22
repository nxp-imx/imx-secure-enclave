// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#ifndef ERR_H
#define ERR_H

#define	SAB_INVALID_MESSAGE	0x01
//!< Invalid/Unknown message.
#define	SAB_INVALID_ADDRESS	0x02
//!< Invalid Address.
#define	SAB_UNKNOWN_ID		0x03
//!< Unknown Id.
#define	SAB_INVALID_PARAM	0x04
//!< MU sanity check failed / Invalid parameters.
#define	SAB_NVM_ERROR		0x05
//!< NVM general error.
#define	SAB_OUT_OF_MEMORY	0x06
//!< Internal memory allocation failed.
#define	SAB_UNKNOWN_HANDLE	0x07
//!< Unknown handle.
#define	SAB_UNKNOWN_KEY_STORE	0x08
//!< Key store with provided key store ID does not exist (load operation).
#define	SAB_KEY_STORE_AUTH	0x09
//!< A key store authentication is failing.
#define	SAB_KEY_STORAGE_ERROR	0x0A
//!< Key store creation/load failure.
#define	SAB_ID_CONFLICT		0x0B
//!< A Key store using the same key id already exists (create operation).
#define	SAB_RNG_NOT_STARTED	0x0C
//!< Internal RNG not started.
#define	SAB_CMD_NOT_SUPPORTED	0x0D
//!< Functionality not supported on current service configuration.
#define	SAB_INVALID_LIFECYCLE	0x0E
//!< Invalid lifecycle for requested operation.
#define	SAB_KEY_STORE_CONFLICT	0x0F
//!< The key store already exists (load operation).
#define	SAB_KEY_STORE_COUNTER	0x10
//!< Issue occurred while updating the key store counter.
#define	SAB_FEATURE_NOT_SUPPORTED 0x11
//!< Feature is not supported.
#define	SAB_SELF_TEST_FAILURE	0x12
//!< Self test execution failed.
#define	SAB_NOT_READY		0x13
//!< System not ready to accept service request.
#define	SAB_FEATURE_DISABLED	0x14
//!< Feature disabled.

#define SAB_FATAL_FAILURE	0xFF
//!< fatal error

#endif
