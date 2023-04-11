/*
 * Copyright 2023 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "sab_storage_key_db.h"

#include "plat_os_abs.h"
#include "plat_utils.h"
#include "plat_os_abs_def.h"

/* Get context key databse pointer switch key store id */
static struct key_db_fd *storage_get_key_db(struct key_db_fd *ctx_key_db,
					    uint32_t key_store_id)
{
	struct key_db_fd *key_db = NULL;

	for (int i = 0; i < MAX_KEY_STORE; i++) {
		if (ctx_key_db[i].key_store_id == key_store_id) {
			key_db = &ctx_key_db[i];
			break;
		}
	}

	return key_db;
}

/* Get context key database unused slot */
static struct key_db_fd *storage_get_key_db_unused_slot(struct key_db_fd *ctx_key_db)
{
	struct key_db_fd *slot = NULL;

	for (int i = 0; i < MAX_KEY_STORE; i++) {
		if (ctx_key_db[i].persistent_tmp_fd < 0 &&
		    ctx_key_db[i].volatile_fd < 0) {
			slot = &ctx_key_db[i];
			break;
		}
	}

	return slot;
}

/*
 * Get the filepath of a key database file. @path is allocated in this function
 * and must be freed by the caller
 */
static uint32_t storage_get_key_db_filepath(char **path, uint8_t *nvm_storage_dname,
					    uint32_t key_store_id, uint8_t pers_lvl,
					    bool tmp_flag)
{
	uint32_t ret = 1u;
	uint64_t blob_id = 0u;

	/* Blob ID is composed this way:
	 *	-Bit 63 to 32: Key store ID;
	 *	-Bit 31 to 16: Temporary file flag (only for persistent);
	 *	-Bit 15 to 8: Persistence level flag;
	 *	-Bit 7 to 0: Block type. Value must not be used by FW
	 */
	blob_id |= (uint64_t)key_store_id << KEY_DB_KEY_STORE_ID_SHIFT;

	if (tmp_flag)
		blob_id |= KEY_DB_TMP_FLAG << KEY_DB_TMP_SHIFT;

	blob_id |= (uint64_t)(pers_lvl << KEY_DB_PERS_LVL_SHIFT);
	blob_id |= KEY_DB_BLOCK_TYPE;

	if (get_chunk_file_path(path, nvm_storage_dname, blob_id) > 0)
		ret = 0u;

	return ret;
}

/*
 * Copy source file content into destination file content. @dst_fd must have
 * been opened in write mode, @src_fd at least in read mode.
 */
static uint32_t storage_copy_file(int dst_fd, int src_fd)
{
	uint32_t err = 1u;
	struct stat f_stat = { 0 };
	char *buffer = NULL;

	/* Get source file attributes */
	if (fstat(src_fd, &f_stat))
		goto out;

	/* Get source file data */
	buffer = calloc(1, (size_t)f_stat.st_size);
	if (!buffer)
		goto out;

	/* Get the file content in @buffer variable */
	if (pread(src_fd, buffer, f_stat.st_size, 0) != f_stat.st_size)
		goto out;

	/* Copy buffer data in dst file */
	if (pwrite(dst_fd, buffer, (size_t)f_stat.st_size, 0) == f_stat.st_size) {
		if (!fsync(dst_fd))
			err = 0u;
	}

out:
	if (buffer)
		free(buffer);

	return err;
}

/* Open a key databse file descriptor switch command flag */
static int storage_open_key_db_fd(uint8_t *nvm_storage_dname,
				  uint32_t key_store_id, uint8_t pers_lvl,
				  uint8_t block_type)
{
	uint32_t ret;
	int fd = -1;
	int _fd;
	char *path = NULL;
	bool tmp_flag = false;

	if (block_type != SAB_STORAGE_KEY_STORE_MASTER_BLOCK_TYPE)
		tmp_flag = pers_lvl == SAB_STORAGE_KEY_PERS_LVL_PERSISTENT ? true : false;

	/*
	 * Here, if @pers_lvl is persistent, we only open and create temporary
	 * file
	 */
	ret = storage_get_key_db_filepath(&path, nvm_storage_dname,
					  key_store_id, pers_lvl, tmp_flag);
	if (ret || !path)
		goto out;

	fd = open(path, KEY_DB_OPEN_CREATE_FLAGS, KEY_DB_OPEN_MODE);
	if (fd < 0)
		goto out;

	if (tmp_flag) {
		/* Check if a persistent file exists */
		free(path);

		ret = storage_get_key_db_filepath(&path, nvm_storage_dname,
						  key_store_id, pers_lvl, false);
		if (ret != 0u)
			goto out;

		_fd = open(path, KEY_DB_OPEN_FLAGS, KEY_DB_OPEN_MODE);
		if (_fd < 0)
			goto out;

		/* Copy persistent file content in temporary persistent file */
		ret = storage_copy_file(fd, _fd);
		if (ret != 0u) {
			(void)close(fd);
			fd = -1;
		}

		(void)close(_fd);
	}

out:
	if (path)
		free(path);

	return fd;
}

/* Close all key database file descriptors */
void storage_close_key_db_fd(struct key_db_fd *ctx_key_db)
{
	for (int i = 0; i < MAX_KEY_STORE; i++) {
		if (ctx_key_db[i].persistent_tmp_fd >= 0) {
			(void)close(ctx_key_db[i].persistent_tmp_fd);
			ctx_key_db[i].persistent_tmp_fd = -1;
		}

		if (ctx_key_db[i].volatile_fd >= 0) {
			(void)close(ctx_key_db[i].volatile_fd);
			ctx_key_db[i].volatile_fd = -1;
		}
	}
}

/*
 * Get a key databse file descriptor. If file is not opened, open it switch
 * operation mode
 */
static int storage_get_key_db_fd(struct key_db_fd *ctx_key_db,
				 uint8_t *nvm_storage_dname,
				 uint32_t key_store_id, uint8_t pers_lvl)
{
	int fd = -1;
	struct key_db_fd *key_db = NULL;

	key_db = storage_get_key_db(ctx_key_db, key_store_id);
	if (!key_db) {
		/* Key store ID not found */
		/* Get a context key database unused slot */
		key_db = storage_get_key_db_unused_slot(ctx_key_db);
		if (!key_db) {
			/*
			 * No free slot, should not be here as no more
			 * than MAX_KEY_STORE can be opened on the FW
			 */
			goto out;
		}

		key_db->key_store_id = key_store_id;
	} else {
		/* Key store ID found */
		if (pers_lvl == SAB_STORAGE_KEY_PERS_LVL_VOLATILE)
			fd = key_db->volatile_fd;
		else
			fd = key_db->persistent_tmp_fd;

		/* Return file descriptor if set, otherwise open/create it */
		if (fd >= 0)
			goto out;
	}

	/* Create or open the key database file */
	fd = storage_open_key_db_fd(nvm_storage_dname, key_store_id, pers_lvl, 0);
	if (fd < 0)
		goto out;

	/* Set file descriptor */
	if (pers_lvl == SAB_STORAGE_KEY_PERS_LVL_VOLATILE)
		key_db->volatile_fd = fd;
	else
		key_db->persistent_tmp_fd = fd;

out:
	return fd;
}

/* Add a pair of IDs in a key database file */
static uint32_t storage_key_db_add(int fd, uint32_t user_id, uint32_t fw_id,
				   uint16_t group)
{
	uint32_t err = 1u;
	struct stat f_stat = { 0 };
	struct key_ids_db ids = {.user_id = user_id,
				 .fw_id = fw_id,
				 .group = group,
				 .flag = KEY_DB_FLAG_NOT_PUSHED };

	/* Get file attributes */
	if (fstat(fd, &f_stat))
		goto out;

	if ((size_t)f_stat.st_size % sizeof(struct key_ids_db)) {
		/* File is corrupted */
		goto out;
	}

	/* Write new entry at the end of the file */
	if ((size_t)pwrite(fd, &ids, sizeof(struct key_ids_db), f_stat.st_size)
		== sizeof(struct key_ids_db)) {
		if (!fsync(fd))
			err = 0u;
	}

out:
	return err;
}

/* Get a FW ID from a key database file */
static uint32_t storage_key_db_get(int fd, uint32_t user_id, uint32_t *fw_id)
{
	uint32_t err = 1u;
	off_t offset = 0;
	struct key_ids_db ids = { 0 };
	struct stat f_stat = { 0 };

	/* Get file attributes */
	if (fstat(fd, &f_stat))
		goto out;

	if ((size_t)f_stat.st_size % sizeof(struct key_ids_db)) {
		/* File is corrupted */
		goto out;
	}

	while (pread(fd, &ids, sizeof(struct key_ids_db), offset) > 0) {
		if (ids.user_id == user_id) {
			if (fw_id) {
				*fw_id = ids.fw_id;
				err = 0u;
			}
			break;
		}
		offset += sizeof(struct key_ids_db);
	}

out:
	return err;
}

/*
 * Delete a pair of IDs in a key database file switch @user_id or @group.
 * If @user_id is 0 (invalid ID), research is based on @group. Otherwise it's
 * based on @user_id.
 *
 * Return:
 * 0 - Success.
 * 1 - General error.
 * 2 - Pair of IDs not found.
 */
static uint32_t storage_key_db_del(int fd, uint32_t user_id, uint16_t group)
{
	uint32_t err = 1u;
	struct stat f_stat = { 0 };
	struct key_ids_db *ids_ptr = NULL;
	off_t file_size = 0;
	void *buffer = NULL;
	bool find = false;

	if (fstat(fd, &f_stat))
		goto out;

	file_size = f_stat.st_size;

	if ((size_t)file_size % sizeof(*ids_ptr)) {
		/* File is corrupted */
		goto out;
	}

	buffer = calloc(1, file_size);
	if (!buffer)
		goto out;

	/* Get the file content in @buffer variable */
	if (pread(fd, buffer, file_size, 0) != file_size)
		goto out;

	ids_ptr = (struct key_ids_db *)buffer;

	do {
		if (user_id == 0u)
			find = ids_ptr->group == group ? true : false;
		else
			find = ids_ptr->user_id == user_id ? true : false;

		if (find)
			break;

		ids_ptr++;
		file_size -= sizeof(*ids_ptr);
	} while (file_size > 0);

	if (file_size == 0) {
		/* End of file, user id not found */
		err = 2u;
		goto out;
	}

	if (file_size > sizeof(*ids_ptr)) {
		/*
		 * Delete ID from file by moving data if this is not the last id
		 * in the file (buffer)
		 */
		file_size -= sizeof(*ids_ptr);
		memmove(ids_ptr, ids_ptr + 1, file_size);
	}

	/* Get new file size: one id structure is deleted */
	file_size = (size_t)f_stat.st_size - sizeof(struct key_ids_db);

	/* Wrtite new data buffer into file */
	if (pwrite(fd, buffer, file_size, 0) == file_size) {
		/* Truncate the file size */
		if (!ftruncate(fd, file_size)) {
			if (!fsync(fd))
				err = 0u;
		}
	}

out:
	if (buffer)
		free(buffer);

	return err;
}

/*
 * Remove invalid key database files (files that are no more valid because
 * volatile or temporary persistent keys)
 */
static uint32_t storage_key_db_remove(uint32_t key_store_id,
				      uint8_t *nvm_storage_dname)
{
	uint32_t ret;
	char *path = NULL;

	/* Remove volatile key database file if any */
	ret = storage_get_key_db_filepath(&path, nvm_storage_dname, key_store_id,
					  SAB_STORAGE_KEY_PERS_LVL_VOLATILE,
					  false);
	if (ret)
		goto out;

	ret = remove(path);
	if (ret && errno != ENOENT)
		goto out;

	free(path);
	path = NULL;

	/* Remove persistent temporary file if any */
	ret = storage_get_key_db_filepath(&path, nvm_storage_dname, key_store_id,
					  SAB_STORAGE_KEY_PERS_LVL_PERSISTENT,
					  true);
	if (ret)
		goto out;

	ret = remove(path);
	if (ret && errno == ENOENT)
		ret = 0u;

out:
	if (path)
		free(path);

	return ret;
}

static uint32_t storage_key_db_close_and_remove(struct key_db_fd *ctx_key_db,
						uint8_t *nvm_storage_dname,
						uint32_t key_store_id)
{
	uint32_t err;

	/* Close all opened key database file descriptor */
	for (int i = 0; i < MAX_KEY_STORE; i++) {
		if (ctx_key_db[i].key_store_id == key_store_id) {
			(void)close(ctx_key_db[i].persistent_tmp_fd);
			ctx_key_db[i].persistent_tmp_fd = -1;

			(void)close(ctx_key_db[i].volatile_fd);
			ctx_key_db[i].volatile_fd = -1;

			break;
		}
	}

	/* Remove volatile and persistent temporary files */
	err = storage_key_db_remove(key_store_id, nvm_storage_dname);

	return err;
}

/*
 * Set all key flags present in group to KEY_DB_FLAG_PUSHED in order to save
 * them in persistent file (storage_key_db_update_pers_file()).
 */
static uint32_t storage_key_db_push_id_flag(int tmp_pers_file_fd, uint16_t group)
{
	uint32_t err = 1u;
	off_t file_offset = 0;
	struct key_ids_db ids = { 0 };
	struct stat f_stat = { 0 };

	if (fstat(tmp_pers_file_fd, &f_stat))
		goto out;

	if ((size_t)f_stat.st_size % sizeof(struct key_ids_db)) {
		/* File is corrupted */
		goto out;
	}

	/* Browse entire file */
	while (pread(tmp_pers_file_fd, &ids, sizeof(struct key_ids_db), file_offset) > 0) {
		/* Update flag of IDs related to the group */
		if (ids.group == group && ids.flag == KEY_DB_FLAG_NOT_PUSHED) {
			/* Update flag in file content */
			ids.flag = KEY_DB_FLAG_PUSHED;

			if (pwrite(tmp_pers_file_fd, &ids, sizeof(struct key_ids_db), file_offset)
				   != sizeof(struct key_ids_db))
				goto out;

			if (fsync(tmp_pers_file_fd))
				goto out;
		}
		file_offset += sizeof(struct key_ids_db);
	}

	/*
	 * If no keys has been found return success. NVM push operation could
	 * has been called after deleting key(s).
	 */
	err = 0u;

out:
	return err;
}

/* Update the key store persistent file key database */
static uint32_t storage_key_db_update_pers_file(uint8_t *nvm_storage_dname,
						struct key_db_fd *key_db)
{
	uint32_t err = 1u;
	int fd;
	uint8_t *buffer = NULL;
	uint32_t buffer_size = 0u;
	uint8_t *ptr = NULL;
	off_t file_offset = 0;
	struct stat f_stat = { 0 };
	struct key_ids_db ids = { 0 };

	/* Get or create persistent key database file */
	fd = storage_open_key_db_fd(nvm_storage_dname, key_db->key_store_id,
				    SAB_STORAGE_KEY_PERS_LVL_PERSISTENT,
				    SAB_STORAGE_KEY_STORE_MASTER_BLOCK_TYPE);
	if (fd < 0)
		goto out;

	/* Check persistent file size */
	if (fstat(fd, &f_stat))
		goto out;

	if (f_stat.st_size % sizeof(struct key_ids_db)) {
		/* File is corrupted */
		goto out;
	}

	/* Get persistent tmp file size to allocate temporary buffer */
	if (fstat(key_db->persistent_tmp_fd, &f_stat))
		goto out;

	if (f_stat.st_size % sizeof(struct key_ids_db)) {
		/* File is corrupted */
		goto out;
	}

	buffer = calloc(1, f_stat.st_size);
	if (!buffer)
		goto out;

	ptr = buffer;

	/* Get all IDs with flag set to KEY_DB_FLAG_PUSHED */
	while (pread(key_db->persistent_tmp_fd, &ids, sizeof(struct key_ids_db), file_offset) > 0) {
		/* Update flag of IDs related to the group */
		if (ids.flag == KEY_DB_FLAG_PUSHED) {
			memcpy(ptr, &ids, sizeof(struct key_ids_db));
			ptr += sizeof(struct key_ids_db);
			buffer_size += sizeof(struct key_ids_db);
		}
		file_offset += sizeof(struct key_ids_db);
	}

	/* Copy buffer content in persistent key database file */
	if (pwrite(fd, buffer, buffer_size, 0) == buffer_size) {
		/* Truncate the file size */
		if (!ftruncate(fd, buffer_size)) {
			if (!fsync(fd))
				err = 0u;
		}
	}

out:
	if (buffer)
		free(buffer);

	/* Close persistent file */
	if (fd >= 0)
		(void)close(fd);

	return err;
}

uint32_t storage_key_db_save_persistent(uint64_t blob_id, struct nvm_ctx_st *nvm_ctx_param)
{
	uint32_t err = 1u;
	uint32_t key_store_id = (uint32_t)(blob_id >> SAB_STORAGE_KEY_STORE_ID_SHIFT);
	uint8_t block_type = (uint8_t)(blob_id & SAB_STORAGE_BLOCK_TYPE_MASK);
	struct key_db_fd *key_db = NULL;

	if (block_type != SAB_STORAGE_CHUNK_BLOCK_TYPE &&
	    block_type != SAB_STORAGE_KEY_STORE_MASTER_BLOCK_TYPE) {
		/* Nothing to do, return success */
		err = 0u;
		goto out;
	}

	key_db = storage_get_key_db(nvm_ctx_param->key_db, key_store_id);
	if (!key_db)
		goto out;

	if (block_type == SAB_STORAGE_CHUNK_BLOCK_TYPE) {
		/* Update flag of keys present in @group */
		err = storage_key_db_push_id_flag(key_db->persistent_tmp_fd,
						  SAB_STORAGE_GET_GROUP(blob_id));
	} else {
		/* block_type == SAB_STORAGE_KEY_STORE_MASTER_BLOCK_TYPE */
		/* Update persistent file */
		err = storage_key_db_update_pers_file(nvm_ctx_param->nvm_dname, key_db);
	}

out:
	return err;
}

uint32_t storage_key_db(struct plat_os_abs_hdl *phdl,
			struct key_db_fd *ctx_key_db,
			uint8_t *nvm_storage_dname, uint32_t *fw_id,
			struct sab_cmd_key_db_msg *msg)
{
	uint32_t err = 1u;
	int fd;

	if (!phdl || phdl->type != MU_CHANNEL_PLAT_HSM_NVM || !ctx_key_db ||
	    !nvm_storage_dname || !fw_id || !msg) {
		goto out;
	}

	/*
	 * Check message flags consistency. One and only one valid flag
	 * must be set
	 */
	if ((bf_popcount(msg->flags & SAB_STORAGE_KEY_DB_ALL_FLAG) != 1u) ||
	    (msg->flags & ~SAB_STORAGE_KEY_DB_ALL_FLAG)) {
		goto out;
	}

	/* Remove invalid key database files */
	if (msg->flags & SAB_STORAGE_KEY_DB_KEYSTORE_OPEN) {
		err = storage_key_db_remove(msg->key_store_id,
					    nvm_storage_dname);
		goto out;
	}

	if (msg->flags & SAB_STORAGE_KEY_DB_KEYSTORE_CLOSE) {
		err = storage_key_db_close_and_remove(ctx_key_db,
						      nvm_storage_dname,
						      msg->key_store_id);
		goto out;
	}

	/* Get key database file descriptor for the operation */
	fd = storage_get_key_db_fd(ctx_key_db, nvm_storage_dname,
				   msg->key_store_id, msg->pers_lvl);
	if (fd < 0)
		goto out;

	if (msg->flags & SAB_STORAGE_KEY_DB_ADD_FLAG) {
		/* Add new pair of IDs in key databse */
		err = storage_key_db_add(fd, msg->user_id, msg->fw_id, msg->group);
	} else if (msg->flags & SAB_STORAGE_KEY_DB_GET_FLAG) {
		/* Get FW ID from key databse */
		err = storage_key_db_get(fd, msg->user_id, fw_id);
	} else { /* SAB_STORAGE_KEY_DB_DEL_FLAG */
		/* Delete a pair of IDs in key database */
		err = storage_key_db_del(fd, msg->user_id, 0);
	}

out:
	return err;
}

uint32_t parse_cmd_prep_rsp_storage_key_db(struct nvm_ctx_st *nvm_ctx_param,
					   void *cmd_buf,
					   void *rsp_buf,
					   uint32_t *cmd_len,
					   uint32_t *rsp_msg_info,
					   void **data,
					   uint32_t *data_sz,
					   uint8_t *prev_cmd_id,
					   uint8_t *next_cmd_id)
{
	uint32_t err;
	uint32_t fw_id = 0u;
	struct sab_cmd_key_db_msg *msg = (struct sab_cmd_key_db_msg *)cmd_buf;
	struct sab_cmd_key_db_rsp *rsp = (struct sab_cmd_key_db_rsp *)rsp_buf;

	*prev_cmd_id = msg->hdr.command;
	*next_cmd_id = NEXT_EXPECTED_CMD_NONE;
	rsp->rsp = SAB_FAILURE_STATUS;

	/* Consistency check of message length. */
	if (*cmd_len != (uint32_t)sizeof(struct sab_cmd_key_db_msg))
		goto out;

	if (*rsp_msg_info != SAB_SUCCESS_STATUS) {
		rsp->rsp = *rsp_msg_info;
		goto out;
	}

	err = storage_key_db(nvm_ctx_param->phdl, nvm_ctx_param->key_db,
			     nvm_ctx_param->nvm_dname, &fw_id, msg);
	if (!err) {
		rsp->rsp = SAB_SUCCESS_STATUS;
		rsp->fw_id = fw_id;
	}

out:
	*rsp_msg_info = sizeof(struct sab_cmd_key_db_rsp);

	return rsp->rsp;
}
