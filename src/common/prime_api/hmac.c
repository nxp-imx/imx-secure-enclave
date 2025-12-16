/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include "sab_prime_process_msg.h"
#include "sab_prime_auth.h"
#include "uio.h"

prime_err_t prime_auth_init(hmac_key_t *args)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();

	return prime_load_hmac_key(prime_mu->base,
				   args->key,
				   args->keylen,
				   args->keyslot,
				   args->sha_algo);
}
