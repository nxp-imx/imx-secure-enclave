/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

#include <stdint.h>
#include <stdio.h>

#include "keyslot.h"
#include "sab_prime_process_msg.h"
#include "sab_prime_aes.h"
#include "sab_prime_mac.h"

static uint64_t hmac_keyslot_map;  // 0 = free, 1 = occupied
static uint64_t aes_keyslot_map;  // 0 = free, 1 = occupied

// Returns index [0–63] of allocated slot, or -1 if none available
uint8_t get_keyslot(uint8_t keyslot_type)
{
	int i;

	if (keyslot_type == HMAC_KEYSLOT) {
		if (hmac_keyslot_map == UINT64_MAX)
			return KEYSLOT_NOT_AVAILABLE; // all bits set

		for (i = 0; i < MAX_PRIME_KEY_SLOT_SUPPORTED; i++) {
			if (!(hmac_keyslot_map & (1ULL << i))) {
				hmac_keyslot_map |= (1ULL << i);  // mark as used
				return i;
			}
		}
	} else if (keyslot_type == AES_KEYSLOT) {
		if (aes_keyslot_map == UINT64_MAX)
			return KEYSLOT_NOT_AVAILABLE; // all bits set

		for (i = 0; i < MAX_PRIME_KEY_SLOT_SUPPORTED; i++) {
			if (!(aes_keyslot_map & (1ULL << i))) {
				aes_keyslot_map |= (1ULL << i);  // mark as used
				return i;
			}
		}
	}
	return KEYSLOT_NOT_AVAILABLE;
}

void release_keyslot(uint64_t keyslot_mask, uint8_t keyslot_type)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();
	uint8_t key[32] = {0};
	int keyslot;

	if (keyslot_type == HMAC_KEYSLOT) {
		// Clear all bits that are set in mask
		hmac_keyslot_map &= ~keyslot_mask;

		// Iterate through all 64 bits
		for (keyslot = 0; keyslot < MAX_PRIME_KEY_SLOT_SUPPORTED; keyslot++)
			// Check if bit is set
			if (keyslot_mask & (1ULL << keyslot))
				if (prime_load_hmac_key(prime_mu->base,
							key,
							32,
							keyslot,
							CRYPTO_AUTH_SHA_256))
					printf("Failed to clear HMAC keyslot %d\n",
					       keyslot);
	} else if (keyslot_type == AES_KEYSLOT) {
		// Clear all bits that are set in mask
		aes_keyslot_map &= ~keyslot_mask;

		// Iterate through all 64 bits
		for (keyslot = 0; keyslot < MAX_PRIME_KEY_SLOT_SUPPORTED; keyslot++)
			// Check if bit is set
			if (keyslot_mask & (1ULL << keyslot))
				if (prime_load_aes_key(prime_mu->base,
						       key,
						       32,
						       keyslot))
					printf("Failed to clear AES keyslot %d\n",
					       keyslot);
	}
}
