// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_STORAGE_KEY_DB_H
#define SAB_STORAGE_KEY_DB_H

#include <fcntl.h>

#include "sab_nvm.h"
#include "sab_msg_def.h"
#include "plat_utils.h"

#define SAB_STORAGE_KEY_DB_ADD_FLAG       BIT(0)
#define SAB_STORAGE_KEY_DB_GET_FLAG       BIT(1)
#define SAB_STORAGE_KEY_DB_DEL_FLAG       BIT(2)
#define SAB_STORAGE_KEY_DB_KEYSTORE_OPEN  BIT(3)
#define SAB_STORAGE_KEY_DB_KEYSTORE_CLOSE BIT(4)
#define SAB_STORAGE_KEY_DB_ALL_FLAG                                \
(SAB_STORAGE_KEY_DB_ADD_FLAG | SAB_STORAGE_KEY_DB_GET_FLAG |       \
SAB_STORAGE_KEY_DB_DEL_FLAG | SAB_STORAGE_KEY_DB_KEYSTORE_OPEN | \
SAB_STORAGE_KEY_DB_KEYSTORE_CLOSE)

#define SAB_STORAGE_KEY_PERS_LVL_VOLATILE   (0u)
#define SAB_STORAGE_KEY_PERS_LVL_PERSISTENT (1u)

#define SAB_STORAGE_KEY_STORE_MASTER_BLOCK_TYPE (3u)
#define SAB_STORAGE_CHUNK_BLOCK_TYPE            (4U)
#define SAB_STORAGE_KEY_STORE_ID_SHIFT          (32u)
#define SAB_STORAGE_BLOCK_TYPE_MASK             (0x00000000000000FFU)
#define SAB_STORAGE_GROUP_MASK                  (0x00000000FFFF0000U)
#define SAB_STORAGE_GROUP_SHIFT                 (16u)
#define SAB_STORAGE_GET_GROUP(blob_id)          \
(((blob_id) & SAB_STORAGE_GROUP_MASK) >> SAB_STORAGE_GROUP_SHIFT)
#define SAB_STORAGE_CHUNK_SWAP_FLAG             (1u)
#define SAB_STORAGE_FLAG_MASK                   (0x000000000000FF00U)
#define SAB_STORAGE_FLAG_SHIFT                  (8u)
#define SAB_STORAGE_GET_FLAG(blob_id)           \
(((blob_id) & SAB_STORAGE_FLAG_MASK) >> SAB_STORAGE_FLAG_SHIFT)

#define KEY_DB_BLOCK_TYPE           0xFFu
#define KEY_DB_TMP_FLAG             0xFFFFu
#define KEY_DB_KEY_STORE_ID_SHIFT   32u
#define KEY_DB_PERS_LVL_SHIFT       8u
#define KEY_DB_TMP_SHIFT            16u
#define KEY_DB_OPEN_FLAGS           (O_RDWR | O_SYNC)
#define KEY_DB_OPEN_CREATE_FLAGS    (KEY_DB_OPEN_FLAGS | O_CREAT)
/*
 * S_IRUSR | S_IWUSR (use hex value because of checkpatch warning: symbolic permissions
 * are not preferred).
 */
#define KEY_DB_OPEN_MODE            (0x600)

#define KEY_DB_FLAG_NOT_PUSHED (0u)
#define KEY_DB_FLAG_PUSHED     (1u)

struct sab_cmd_key_db_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_store_id;
	uint32_t user_id;
	uint32_t fw_id;
	uint8_t flags;
	uint8_t pers_lvl;
	uint16_t group;
	uint32_t crc;
};

struct sab_cmd_key_db_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp;
	uint32_t fw_id;
};

struct key_ids_db {
	uint32_t user_id; /* User key identifier */
	uint32_t fw_id;   /* Internal FW key identifier */
	uint16_t group;   /* Key group */
	uint16_t flag;    /* Key flag */
};

/*
 * Called by sab_storage_export_finish. Save a copy of the current persistent
 * key store key database
 */
uint32_t storage_key_db_save_persistent(uint64_t blob_id,
					struct nvm_ctx_st *nvm_ctx_param);

/* Close all opened key database files descriptor */
void storage_close_key_db_fd(struct key_db_fd *ctx_key_db);

uint32_t parse_cmd_prep_rsp_storage_key_db(struct nvm_ctx_st *nvm_ctx_param,
					   void *cmd_buf,
					   void *rsp_buf,
					   uint32_t *cmd_len,
					   uint32_t *rsp_msg_info,
					   void **data,
					   uint32_t *data_sz,
					   uint8_t *prev_cmd_id,
					   uint8_t *next_cmd_id);

#endif
