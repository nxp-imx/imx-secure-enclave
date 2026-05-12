/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include "sab_prime_process_msg.h"
#include "sab_prime_aes.h"
#include "keyslot.h"
#include "utils.h"

prime_err_t prime_cipher_init(prime_hdl_t service_hdl, aes_key_t *args)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();
	prime_service_t *hdl;

	hdl = prime_session_to_ptr(service_hdl);
	if (!hdl) {
		printf("Invalid handle\n");
		return PRIME_ERROR;
	}

	args->keyslot = get_keyslot(AES_KEYSLOT);

	if (args->keyslot == KEYSLOT_NOT_AVAILABLE)
		return PRIME_ERROR;

	hdl->aes_keyslot_map |= BIT(args->keyslot);

	return prime_load_aes_key(prime_mu->base,
				  args->key,
				  args->keylen,
				  args->keyslot);
}
