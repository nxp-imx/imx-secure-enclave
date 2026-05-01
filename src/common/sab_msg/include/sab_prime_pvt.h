/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#ifndef SAB_PRIME_PVT_H
#define SAB_PRIME_PVT_H

#include <stdint.h>

#include "prime.h"
#include "uio.h"

int prime_mac_build(prime_service_t *hdl,
		    crypto_op_args_t *op,
		    uint8_t buf_off,
		    uint8_t flag);

int prime_cipher_build(prime_service_t *hdl,
		       crypto_op_args_t *op,
		       uint8_t buf_off,
		       uint8_t flag);

int prime_aead_build(prime_service_t *hdl,
		     crypto_op_args_t *op,
		     uint8_t buf_off,
		     uint8_t flag);

#endif /* SAB_PRIME_PVT_H */
