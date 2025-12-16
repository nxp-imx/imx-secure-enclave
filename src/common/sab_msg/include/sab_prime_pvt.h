/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#ifndef SAB_PRIME_PVT_H
#define SAB_PRIME_PVT_H

#include <stdint.h>

#include "prime.h"

int prime_auth_build(crypto_op_args_t *op,
		     uint8_t buf_off,
		     uint8_t flag);

int prime_cipher_build(crypto_op_args_t *op,
		       uint8_t buf_off,
		       uint8_t flag);

int prime_aead_build(crypto_op_args_t *op,
		     uint8_t buf_off,
		     uint8_t flag);

#endif /* SAB_PRIME_PVT_H */
