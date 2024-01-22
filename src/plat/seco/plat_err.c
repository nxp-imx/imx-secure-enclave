// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include "sab_common_err.h"

//NOTE: To make changes in error description according to SECO
static struct sab_err_map_s sab_err_str_map[] = {
	{0x00D6, "Operation Successful"},
	{0x0029, "General Error"},
	{0x0129, "Invalid/Unknown message"},
	{0x0229, "Invalid Address"},
	{0x0329, "Unknown Id"},
	{0x0429, "MU sanity check failed / Invalid parameters"},
	{0x0529, "NVM general error"},
	{0x0629, "Internal memory allocation failed"},
	{0x0729, "Unknown handle"},
	{0x0829, "Key store with provided key store ID does not exist (load operation)"},
	{0x0929, "A key store authentication is failing"},
	{0x0A29, "Key store creation/load failure"},
	{0x0B29, "A Key store using the same key id already exists (create operation)"},
	{0x0C29, "Internal RNG not started"},
	{0x0D29, "Functionality not supported on current service configuration"},
	{0x0E29, "Invalid lifecycle for requested operation"},
	{0x0F29, "The key store already exists (load operation)"},
	{0x1029, "Issue occurred while updating the key store counter"},
	{0x1129, "Feature is not supported"},
	{0x1229, "Self test execution failed"},
	{0x1329, "System not ready to accept service request"},
	{0x1429, "Feature disabled"},
	{0x1829, "Invalid Signature in SIGNED message"},
	{0x1929, "Not enough space to store the key in the key group"},
	{0x1A29, "Impossible to retrieve chunk"},
	{0x1B29, "Key not supported"},
	{0x1C29, "Trying to delete a permanent key"},
	{0x1D29, "Output public key size is too small"},
	{0xB929, "Command CRC check error"},
	{0xD129, "Invalid sequence of commands"},
	{0xD229, "Key is locked"},
	{0xD329, "Key not allowed for the given operation"},
	{0xD429, "Key has not been initialized yet"},
	{0xD529, "Conditions for a secure boot process are not met"},
	{0xD629, "Memory slot for this key has been write-protected"},
	{0xD729, "Key update did not succeed, errors in verification of message"},
	{0xD829, "The seed has not been initialized"},
	{0xD929, "Internal debugging is not possible"},
	{0xDA29, "SHE is busy"},
	{0xDB29, "Memory Error"},
	{0xDC29, "SHE General error"},
	{0xFF29, "Fatal Error"},
};

struct sab_err_map_s *get_sab_err_str_map(void)
{
	return sab_err_str_map;
}
