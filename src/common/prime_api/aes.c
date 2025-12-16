/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include "sab_prime_process_msg.h"
#include "sab_prime_aes.h"
#include "uio.h"

prime_err_t prime_cipher_init(aes_key_t *args)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();

	return prime_load_aes_key(prime_mu->base,
				  args->key,
				  args->keylen,
				  args->keyslot);
}
