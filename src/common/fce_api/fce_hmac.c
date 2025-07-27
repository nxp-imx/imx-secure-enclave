/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include "sab_fce_process_msg.h"
#include "sab_fce_auth.h"
#include "fce_uio.h"

prime_err_t prime_auth_init(hmac_key_t *args)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();

	return fce_load_hmac_key(fce_mu->base,
				 args->key,
				 args->keylen,
				 args->keyslot,
				 args->sha_algo);
}
