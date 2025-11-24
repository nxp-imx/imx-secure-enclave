/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#ifndef SAB_FCE_PVT_H
#define SAB_FCE_PVT_H

#include <stdint.h>

#include "fce.h"

int fce_auth_build(crypto_op_args_t *op,
		   uint8_t buf_off,
		   uint8_t flag);

int fce_cipher_build(crypto_op_args_t *op,
		     uint8_t buf_off,
		     uint8_t flag);

int fce_aead_build(crypto_op_args_t *op,
		   uint8_t buf_off,
		   uint8_t flag);

#endif /* SAB_FCE_PVT_H */
