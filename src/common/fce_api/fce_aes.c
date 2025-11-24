/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include "sab_fce_process_msg.h"
#include "sab_fce_aes.h"
#include "fce_uio.h"

fce_err_t fce_cipher_init(aes_key_t *args)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();

	return fce_load_aes_key(fce_mu->base,
				 args->key,
				 args->keylen,
				 args->keyslot);
}
