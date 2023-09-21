// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "sab_common_err.h"

static struct sab_err_map_s sab_err_str_map[SAB_ERR_MAP_N] = {
	{0x00D6, "Operation Successful"},
	{0x0029, "General Error"},
	{0x0229, "Invalid Address"},
	{0x0329, "Provided key-id, Unknown to key store."},
	{0x0429, "MU sanity check failed / Invalid parameters"},
	{0x0629, "Internal memory allocation failed"},
	{0x0729, "Unknown handle"},
	{0x0829, "Key store with provided key store ID doesn’t exist (load operation)"},
	{0x0929, "A key store authentication is failing"},
	{0x0A29, "Key store creation/load failure"},
	{0x0B29, "A Key store using the same key id already exists (create operation)"},
	{0x0C29, "Failure while generating random"},
	{0x0F29, "The key store is already opened by a user (load operation)"},
	{0x1029, "Issue occurred while updating the key store counter"},
	{0x1129, "Algorithm (Key exchange scheme, KDF algo) is not supported"},
	{0x1429, "Feature disabled"},
	{0x1829, "Invalid Signature in SIGNED message"},
	{0x1929, "Not enough space to store the key in the key group"},
	{0x1A29, "Impossible to retrieve chunk"},
	{0x1B29, "Key not supported"},
	{0x1C29, "Trying to delete a permanent key"},
	{0x1D29, "Output public key size is too small"},
	{0xB929, "Command CRC check error"},
	{0xF229, "Invalid Lifecycle operation"},
};


struct sab_err_map_s *get_sab_err_str_map(void)
{
	return sab_err_str_map;
}
