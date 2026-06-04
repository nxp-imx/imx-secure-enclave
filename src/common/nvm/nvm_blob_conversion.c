// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#ifdef PSA_COMPLIANT
#include <sys/stat.h>
#include <limits.h>

#include "nvm_blob_conversion.h"
#include "plat_os_abs.h"
#include "plat_utils.h"

/* Backup file suffix and related size calculations */
#define BACKUP_SUFFIX ".v1_backup"
#define BACKUP_SUFFIX_LEN 11  /* Length of ".v1_backup" string */
#define PATH_SEPARATOR_LEN 1   /* Length of "/" character */
#define NULL_TERMINATOR_LEN 1  /* Length of null terminator */

/* Total overhead for backup filepath: "/" + ".v1_backup" + null */
#define BACKUP_PATH_OVERHEAD (PATH_SEPARATOR_LEN + BACKUP_SUFFIX_LEN \
			      + NULL_TERMINATOR_LEN)

/* Overhead for simple path construction: "/" + null */
#define PATH_OVERHEAD (PATH_SEPARATOR_LEN + NULL_TERMINATOR_LEN)

/* Initial capacity for converted files tracking list */
#define CONVERTED_FILES_INITIAL_CAPACITY 16

/* Structure to track converted files for rollback */
typedef struct {
	uint8_t **files;
	uint32_t count;
	uint32_t capacity;
} converted_files_list_t;

uint8_t nvm_get_current_header_version(void)
{
	return NVM_HEADER_SZ;
}

/* Initialize the converted files list */
static uint32_t init_converted_files_list(converted_files_list_t *list,
					  uint32_t initial_capacity)
{
	size_t size;

	if (!list) {
		printf("Error: Invalid list pointer\n");
		return 1;
	}

	if (initial_capacity == 0 ||
	    initial_capacity > (UINT32_MAX / sizeof(uint8_t *))) {
		printf("Error: Invalid initial capacity\n");
		return 1;
	}

	size = (size_t)initial_capacity * sizeof(uint8_t *);

	list->files = (uint8_t **)plat_os_abs_malloc((uint32_t)size);
	if (!list->files) {
		printf("Error: Failed to allocate memory for converted files list\n");
		return 1;
	}

	list->capacity = initial_capacity;
	list->count = 0;

	return 0;
}

/* Expand the converted files list capacity */
static uint32_t expand_converted_files_list(converted_files_list_t *list)
{
	uint32_t new_capacity;
	size_t size;
	size_t copy_size;
	uint8_t **new_files;

	if (!list) {
		printf("Error: Invalid list pointer\n");
		return 1;
	}

	if (!list->files) {
		printf("Error: Failed to fetch converted files list\n");
		return 1;
	}

	/* Check for overflow when doubling capacity */
	if (list->capacity > (UINT32_MAX / 2)) {
		printf("Error: Capacity expansion would overflow\n");
		return 1;
	}

	new_capacity = list->capacity * 2;

	if (new_capacity > (UINT32_MAX / sizeof(uint8_t *))) {
		printf("Error: Size calculation would overflow\n");
		return 1;
	}

	size = (size_t)new_capacity * sizeof(uint8_t *);

	new_files = (uint8_t **)plat_os_abs_malloc((uint32_t)size);
	if (!new_files) {
		printf("Error: Failed to expand converted files list\n");
		return 1;
	}

	/* Check for overflow before calculating copy size */
	if (list->capacity > (UINT32_MAX / sizeof(uint8_t *))) {
		printf("Error: Copy size calculation would overflow\n");
		plat_os_abs_free(new_files);
		return 1;
	}

	copy_size = (size_t)list->capacity * sizeof(uint8_t *);

	/* Copy existing pointers to new array */
	plat_os_abs_memcpy((uint8_t *)new_files, (uint8_t *)list->files,
			   (uint32_t)copy_size);

	plat_os_abs_free(list->files);
	list->files = new_files;
	list->capacity = new_capacity;

	return 0;
}

/* Add a file to the converted files list */
static uint32_t add_to_converted_files_list(converted_files_list_t *list,
					    uint8_t *filepath)
{
	size_t path_len;

	if (!list || !filepath) {
		printf("Error: Invalid parameters\n");
		return 1;
	}

	/* Expand list if needed */
	if (list->count >= list->capacity) {
		if (expand_converted_files_list(list) != 0)
			return 1;
	}

	/* Allocate and store filepath */
	path_len = strlen((char *)filepath);

	if (path_len >= UINT32_MAX) {
		printf("Error: Path length too large\n");
		return 1;
	}

	path_len += NULL_TERMINATOR_LEN;

	if (!list->files) {
		printf("Error: No files list available\n");
		return 1;
	}

	list->files[list->count] = plat_os_abs_malloc((uint32_t)path_len);
	if (!list->files[list->count]) {
		printf("Error: Failed to allocate memory for filepath tracking\n");
		return 1;
	}

	plat_os_abs_memcpy(list->files[list->count], filepath, (uint32_t)path_len);
	list->count++;

	return 0;
}

/* Free the converted files list */
static void free_converted_files_list(converted_files_list_t *list)
{
	uint32_t i;

	if (!list)
		return;

	if (list->files) {
		for (i = 0; i < list->count; i++) {
			if (list->files[i])
				plat_os_abs_free(list->files[i]);
		}
		plat_os_abs_free(list->files);
	}

	list->files = NULL;
	list->count = 0;
	list->capacity = 0;
}

/* Create backup of a blob file */
static uint32_t create_blob_backup(struct nvm_ctx_st *nvm_ctx,
				   uint8_t *blob_data,
				   uint32_t blob_size,
				   uint8_t *backup_fpath)
{
	if (!nvm_ctx || !blob_data || !backup_fpath || blob_size == 0) {
		printf("Error: Invalid parameters for backup creation\n");
		return 1;
	}

	if (plat_os_abs_storage_write(nvm_ctx->phdl,
				      blob_data,
				      blob_size,
				      backup_fpath) != blob_size) {
		printf("Error: Failed to create backup: %s\n", backup_fpath);
		return 1;
	}

	return 0;
}

/* Delete backup file */
static void delete_blob_backup(struct nvm_ctx_st *nvm_ctx,
			       uint8_t *backup_fpath)
{
	if (!nvm_ctx || !backup_fpath)
		return;

	plat_os_abs_storage_delete(nvm_ctx->phdl, backup_fpath);
}

/* Restore blob from backup */
static uint32_t restore_blob_from_backup(struct nvm_ctx_st *nvm_ctx,
					 uint8_t *filepath,
					 uint8_t *backup_fpath)
{
	uint8_t *rollback_data = NULL;
	uint32_t rollback_size = 0;
	uint32_t ret = 0;

	if (!nvm_ctx || !filepath || !backup_fpath) {
		printf("Error: Invalid parameters for restore\n");
		return 1;
	}

	/* Get the actual backup file size from the filesystem */
	rollback_size = plat_os_abs_storage_get_size(nvm_ctx->phdl, backup_fpath);
	if (rollback_size == 0) {
		printf("Error: Failed to get backup file size or file is empty: %s\n",
		       backup_fpath);
		return 1;
	}

	/* Allocate buffer for backup data */
	rollback_data = plat_os_abs_malloc(rollback_size);
	if (!rollback_data) {
		printf("Error: Failed to allocate memory for restore: %s\n",
		       filepath);
		return 1;
	}

	/* Read backup file */
	if (plat_os_abs_storage_read(nvm_ctx->phdl,
				     rollback_data,
				     rollback_size,
				     backup_fpath) != rollback_size) {
		printf("Error: Failed to read backup: %s\n", backup_fpath);
		plat_os_abs_free(rollback_data);
		return 1;
	}

	/* Truncate the corrupted file to the backup size before writing
	 * This ensures no extra bytes remain at the end if the corrupted
	 * file is larger than the backup (e.g., V2 file larger than V1 backup)
	 */
	if (plat_os_abs_storage_truncate(nvm_ctx->phdl,
					 filepath,
					 rollback_size) != PLAT_SUCCESS) {
		printf("Warning: Failed to truncate file, deleting and recreating: %s\n",
		       filepath);
		/* If truncate fails, delete the file completely */
		plat_os_abs_storage_delete(nvm_ctx->phdl, filepath);
	}

	/* Restore original V1 blob */
	if (plat_os_abs_storage_write(nvm_ctx->phdl,
				      rollback_data,
				      rollback_size,
				      filepath) != rollback_size) {
		printf("Error: Failed to restore blob: %s\n", filepath);
		ret = 1;
	} else {
		printf("Restored: %s (%u bytes)\n", filepath, rollback_size);
	}

	plat_os_abs_free(rollback_data);
	return ret;
}

/* Rollback all converted files */
static void rollback_converted_blobs(struct nvm_ctx_st *nvm_ctx,
				     converted_files_list_t *converted_list)
{
	uint8_t backup_fpath[MAX_FNAME_DNAME_SZ * 2];
	uint32_t i;
	uint8_t *file_slash;
	int snprintf_ret;
	size_t dirname_len;
	size_t fname_len;
	size_t available_space;

	if (!nvm_ctx || !converted_list)
		return;

	printf("\nConversion failed! Rolling back all converted files...\n");

	dirname_len = strlen((char *)nvm_ctx->nvm_dname);

	if (converted_list->count == 0)
		return;

	i = converted_list->count;
	do {
		i--;

		if (!converted_list->files || !converted_list->files[i])
			continue;

		/* Construct backup file path */
		plat_os_abs_memset(backup_fpath, 0, sizeof(backup_fpath));

		/* Extract filename from full path */
		file_slash = (uint8_t *)strrchr((char *)converted_list->files[i], '/');

		if (file_slash) {
			fname_len = strlen((char *)(file_slash + 1));

			if (fname_len > (SIZE_MAX - BACKUP_PATH_OVERHEAD)) {
				printf("Error: Filename too long (backup), skip: %s\n",
				       converted_list->files[i]);
				continue;
			}

			if (sizeof(backup_fpath) <
			    (fname_len + BACKUP_PATH_OVERHEAD)) {
				printf("Error: Backup path too long, skipping: %s\n",
				       converted_list->files[i]);
				continue;
			}

			available_space =
				sizeof(backup_fpath) - fname_len - BACKUP_PATH_OVERHEAD;

			/* Check for overflow:
			 * dirname + "/" + filename + ".v1_backup" + null
			 */
			if (dirname_len > available_space) {
				printf("Error: Backup path too long, skipping: %s\n",
				       converted_list->files[i]);
				continue;
			}

			snprintf_ret = snprintf((char *)backup_fpath,
						sizeof(backup_fpath),
						"%s/%s" BACKUP_SUFFIX,
						nvm_ctx->nvm_dname,
						file_slash + 1);
		} else {
			fname_len = strlen((char *)converted_list->files[i]);

			if (fname_len > (SIZE_MAX - BACKUP_PATH_OVERHEAD)) {
				printf("Error: Filename too long (backup), skip: %s\n",
				       converted_list->files[i]);
				continue;
			}

			if (sizeof(backup_fpath) <
			    (fname_len + BACKUP_PATH_OVERHEAD)) {
				printf("Error: Backup path too long, skipping: %s\n",
				       converted_list->files[i]);
				continue;
			}

			available_space =
				sizeof(backup_fpath) - fname_len - BACKUP_PATH_OVERHEAD;

			if (dirname_len > available_space) {
				printf("Error: Backup path too long, skipping: %s\n",
				       converted_list->files[i]);
				continue;
			}

			snprintf_ret = snprintf((char *)backup_fpath,
						sizeof(backup_fpath),
						"%s/%s" BACKUP_SUFFIX,
						nvm_ctx->nvm_dname,
						converted_list->files[i]);
		}

		if (snprintf_ret < 0 || (size_t)snprintf_ret >= sizeof(backup_fpath)) {
			printf("Error: Failed to construct backup path for: %s\n",
			       converted_list->files[i]);
			continue;
		}

		restore_blob_from_backup(nvm_ctx,
					 converted_list->files[i],
					 backup_fpath);

		delete_blob_backup(nvm_ctx, backup_fpath);
	} while (i > 0);

	printf("Rollback complete. All files reverted to V1 format.\n");
}

/* Delete all backup files after successful conversion */
static void cleanup_backup_files(struct nvm_ctx_st *nvm_ctx,
				 converted_files_list_t *converted_list)
{
	uint8_t backup_fpath[MAX_FNAME_DNAME_SZ * 2];
	uint32_t i;
	uint8_t *file_slash;
	int snprintf_ret;
	size_t dirname_len;
	size_t fname_len;
	size_t available_space;

	if (!nvm_ctx || !converted_list)
		return;

	dirname_len = strlen((char *)nvm_ctx->nvm_dname);

	for (i = 0; i < converted_list->count; i++) {
		if (!converted_list->files || !converted_list->files[i])
			continue;

		/* Construct backup file path */
		plat_os_abs_memset(backup_fpath, 0, sizeof(backup_fpath));

		/* Extract filename from full path */
		file_slash = (uint8_t *)strrchr((char *)converted_list->files[i], '/');

		if (file_slash) {
			fname_len = strlen((char *)(file_slash + 1));

			if (fname_len > (SIZE_MAX - BACKUP_PATH_OVERHEAD)) {
				printf("Error: Filename too long (backup), skip: %s\n",
				       converted_list->files[i]);
				continue;
			}

			if (sizeof(backup_fpath) <
			    (fname_len + BACKUP_PATH_OVERHEAD)) {
				printf("Error: Backup path too long, skipping: %s\n",
				       converted_list->files[i]);
				continue;
			}

			available_space =
				sizeof(backup_fpath) - fname_len - BACKUP_PATH_OVERHEAD;

			if (dirname_len > available_space) {
				printf("Error: Backup path too long, skipping: %s\n",
				       converted_list->files[i]);
				continue;
			}

			snprintf_ret = snprintf((char *)backup_fpath,
						sizeof(backup_fpath),
						"%s/%s" BACKUP_SUFFIX,
						nvm_ctx->nvm_dname,
						file_slash + 1);
		} else {
			fname_len = strlen((char *)converted_list->files[i]);

			if (fname_len > (SIZE_MAX - BACKUP_PATH_OVERHEAD)) {
				printf("Error: Filename too long (backup), skip: %s\n",
				       converted_list->files[i]);
				continue;
			}

			if (sizeof(backup_fpath) <
			    (fname_len + BACKUP_PATH_OVERHEAD)) {
				printf("Error: Backup path too long, skipping: %s\n",
				       converted_list->files[i]);
				continue;
			}

			available_space =
				sizeof(backup_fpath) - fname_len - BACKUP_PATH_OVERHEAD;

			if (dirname_len > available_space) {
				printf("Error: Backup path too long, skipping: %s\n",
				       converted_list->files[i]);
				continue;
			}

			snprintf_ret = snprintf((char *)backup_fpath,
						sizeof(backup_fpath),
						"%s/%s" BACKUP_SUFFIX,
						nvm_ctx->nvm_dname,
						converted_list->files[i]);
		}

		if (snprintf_ret < 0 || (size_t)snprintf_ret >= sizeof(backup_fpath)) {
			printf("Error: Failed to construct backup path for: %s\n",
			       converted_list->files[i]);
			continue;
		}

		delete_blob_backup(nvm_ctx, backup_fpath);
	}

	printf("Cleanup complete. All backup files removed.\n");
}

/* Read a V1 blob from storage */
static uint32_t read_v1_blob(struct nvm_ctx_st *nvm_ctx,
			     uint8_t *filepath,
			     uint8_t **blob_data,
			     uint32_t *blob_size)
{
	uint32_t actual_file_size = 0;

	if (!nvm_ctx || !filepath || !blob_data || !blob_size) {
		printf("Error: Invalid parameters for reading v1 blob\n");
		return 1;
	}

	/* Initialize output parameters */
	*blob_data = NULL;
	*blob_size = 0;

	/* Get the actual file size from the filesystem */
	actual_file_size = plat_os_abs_storage_get_size(nvm_ctx->phdl, filepath);
	if (actual_file_size == 0) {
		printf("Error: Failed to get file size or file is empty: %s\n",
		       filepath);
		return 1;
	}

	/* Use the actual file size from filesystem, not the header's size field */
	*blob_size = actual_file_size;

	/* Allocate buffer for V1 blob */
	*blob_data = plat_os_abs_malloc(*blob_size);
	if (!*blob_data) {
		printf("Error: Failed to allocate memory for blob: %s\n", filepath);
		*blob_size = 0;
		return 1;
	}

	/* Read the entire V1 blob based on actual file size */
	if (plat_os_abs_storage_read(nvm_ctx->phdl,
				     *blob_data,
				     *blob_size,
				     filepath) != *blob_size) {
		printf("Error: Failed to read V1 blob data: %s\n", filepath);
		plat_os_abs_free(*blob_data);
		*blob_data = NULL;
		*blob_size = 0;
		return 1;
	}

	return 0;
}

/* Convert a single V1 blob to V2 format */
static uint32_t convert_blob_v1_to_v2(uint8_t *v1_blob_data,
				      uint32_t v1_blob_size,
				      uint8_t **v2_blob_data,
				      uint32_t *v2_blob_size,
				      uint8_t is_master_blob)
{
	struct nvm_header_s *nvm_hdr = NULL;
	uint32_t *data_ptr = NULL;
	uint32_t new_crc = 0;
	uint32_t size_increase = 0;
	uint32_t remaining_data_size;

	if (!v1_blob_data || !v2_blob_data || !v2_blob_size || v1_blob_size < 20) {
		printf("Error: Invalid parameters for conversion\n");
		return 1;
	}

	/* Initialize output parameters */
	*v2_blob_data = NULL;
	*v2_blob_size = 0;

	if (v1_blob_size > (UINT32_MAX - 4)) {
		printf("Error: V1 blob size too large for conversion\n");
		return 1;
	}

	/* Calculate new blob size (V1 size + 4 bytes for reserved field) */
	*v2_blob_size = v1_blob_size + 4;

	/* Allocate new buffer for V2 blob */
	*v2_blob_data = plat_os_abs_malloc(*v2_blob_size);
	if (!*v2_blob_data) {
		printf("Error: Failed to allocate memory for V2 blob\n");
		*v2_blob_size = 0;
		return 1;
	}

	/* Step 1: Copy first 20 bytes (V1 header) */
	plat_os_abs_memcpy(*v2_blob_data, v1_blob_data, 20);

	/* Step 2: Insert 4 zero bytes at offset 20 (new reserved field in V2) */
	plat_os_abs_memset(*v2_blob_data + 20, 0, 4);

	/* Step 3: Copy remaining data (from offset 20 in V1 to offset 24 in V2) */
	remaining_data_size = v1_blob_size - 20;
	plat_os_abs_memcpy(*v2_blob_data + 24,
			   v1_blob_data + 20,
			   remaining_data_size);

	/* Step 4: Update NVM header size field */
	nvm_hdr = (struct nvm_header_s *)(*v2_blob_data);

	if (is_master_blob) {
		/* Master blob: increase by 20 (full V1 header size) */
		size_increase = 20;
	} else {
		/* Chunk blob: increase by 4 (reserved field only) */
		size_increase = 4;
	}

	if (nvm_hdr->size > (UINT32_MAX - size_increase)) {
		printf("Error: Header size update would overflow\n");
		plat_os_abs_free(*v2_blob_data);
		*v2_blob_data = NULL;
		*v2_blob_size = 0;
		return 1;
	}

	nvm_hdr->size = nvm_hdr->size + size_increase;

	/* Step 5: Recalculate XOR-CRC from offset 24 onward */
	if (nvm_hdr->size < 24) {
		printf("Error: Invalid header size for CRC calculation\n");
		plat_os_abs_free(*v2_blob_data);
		*v2_blob_data = NULL;
		*v2_blob_size = 0;
		return 1;
	}

	data_ptr = (uint32_t *)(*v2_blob_data + 20);
	new_crc = plat_fetch_msg_crc(data_ptr, nvm_hdr->size - 20);

	/* Update CRC in the header */
	nvm_hdr->crc = new_crc;

	return 0;
}

/* Write a V2 blob to storage */
static uint32_t write_v2_blob(struct nvm_ctx_st *nvm_ctx,
			      uint8_t *filepath,
			      uint8_t *v2_blob_data,
			      uint32_t v2_blob_size)
{
	if (!nvm_ctx || !filepath || !v2_blob_data || v2_blob_size == 0) {
		printf("Error: Invalid parameters for writing v2 blob\n");
		return 1;
	}

	if (plat_os_abs_storage_write(nvm_ctx->phdl,
				      v2_blob_data,
				      v2_blob_size,
				      filepath) != v2_blob_size) {
		printf("Error: Failed to write V2 blob: %s\n", filepath);
		return 1;
	}

	return 0;
}

/* Convert a single blob file from V1 to V2 */
static uint32_t convert_single_blob_file(struct nvm_ctx_st *nvm_ctx,
					 uint8_t *filepath,
					 uint8_t *backup_fpath,
					 uint8_t is_master_blob)
{
	uint8_t *v1_blob_data = NULL;
	uint8_t *v2_blob_data = NULL;
	uint32_t v1_blob_size = 0;
	uint32_t v2_blob_size = 0;
	uint32_t ret = 0;

	if (!nvm_ctx || !filepath || !backup_fpath) {
		printf("Error: Invalid parameters for converting single blob file\n");
		return 1;
	}

	/* Read V1 blob */
	if (read_v1_blob(nvm_ctx, filepath, &v1_blob_data, &v1_blob_size) != 0)
		return 1;

	/* Create backup before conversion */
	if (create_blob_backup(nvm_ctx, v1_blob_data, v1_blob_size,
			       backup_fpath) != 0) {
		plat_os_abs_free(v1_blob_data);
		return 1;
	}

	/* Convert V1 to V2 */
	if (convert_blob_v1_to_v2(v1_blob_data, v1_blob_size,
				  &v2_blob_data, &v2_blob_size,
				  is_master_blob) != 0) {
		plat_os_abs_free(v1_blob_data);
		return 1;
	}

	/* Write V2 blob */
	if (write_v2_blob(nvm_ctx, filepath, v2_blob_data, v2_blob_size) != 0)
		ret = 1;

	/* Clean up */
	plat_os_abs_free(v1_blob_data);
	if (v2_blob_data)
		plat_os_abs_free(v2_blob_data);

	return ret;
}

/* Extract master filename from full path */
static void extract_master_filename(struct nvm_ctx_st *nvm_ctx,
				    uint8_t *master_filename,
				    uint32_t max_len)
{
	uint8_t *last_slash;
	size_t fname_len;

	if (!nvm_ctx || !master_filename || max_len == 0)
		return;

	plat_os_abs_memset(master_filename, 0, max_len);

	last_slash = (uint8_t *)strrchr((char *)nvm_ctx->nvm_fname, '/');

	if (last_slash) {
		/* nvm_fname contains full path, extract just the filename */
		fname_len = strlen((char *)(last_slash + 1));

		if (fname_len >= max_len) {
			printf("Warning: Master filename truncated\n");
			fname_len = max_len - 1;
		}

		plat_os_abs_memcpy(master_filename, last_slash + 1,
				   (uint32_t)fname_len);
	} else {
		/* nvm_fname is just a filename */
		fname_len = strlen((char *)nvm_ctx->nvm_fname);

		if (fname_len >= max_len) {
			printf("Warning: Master filename truncated\n");
			fname_len = max_len - 1;
		}

		plat_os_abs_memcpy(master_filename, nvm_ctx->nvm_fname,
				   (uint32_t)fname_len);
	}
}

/* Check if a filename should be skipped during conversion */
static uint8_t should_skip_file(uint8_t *filename)
{
	if (!filename)
		return 1;

	/* Skip "." and ".." entries */
	if (strcmp((char *)filename, ".") == 0 ||
	    strcmp((char *)filename, "..") == 0)
		return 1;

	/* Skip backup files from previous conversions */
	if (strstr((char *)filename, BACKUP_SUFFIX) ||
	    strstr((char *)filename, ".v2_backup"))
		return 1;

	return 0;
}

/* Recover from interrupted conversion by restoring backups */
static uint8_t nvm_blobs_recover_from_interrupted_conversion(struct nvm_ctx_st *nvm_ctx)
{
	void *dir_handle = NULL;
	uint8_t *filename = NULL;
	uint8_t filepath[MAX_FNAME_DNAME_SZ * 2];
	uint8_t backup_fpath[MAX_FNAME_DNAME_SZ * 2];
	uint8_t recovery_performed = 0;
	size_t suffix_len;
	char *backup_pos = NULL;
	size_t fname_len = 0;
	size_t original_name_len = 0;
	int snprintf_ret;
	size_t dirname_len;
	size_t remaining_space;
	size_t available_space;

	if (!nvm_ctx) {
		printf("Error: Invalid nvm_ctx\n");
		return 0;
	}

	suffix_len = BACKUP_SUFFIX_LEN;

	printf("\n=== Checking for interrupted conversion ===\n");

	/* Open directory containing NVM blobs */
	dir_handle = plat_os_abs_open_dir(nvm_ctx->nvm_dname);
	if (!dir_handle) {
		printf("Error: Failed to open directory for recovery check: %s\n",
		       nvm_ctx->nvm_dname);
		return 0;
	}

	dirname_len = strlen((char *)nvm_ctx->nvm_dname);

	/* Look for any backup files */
	while ((filename = plat_os_abs_read_dir(dir_handle)) != NULL) {
		/* Skip non-backup files */
		backup_pos = strstr((char *)filename, BACKUP_SUFFIX);
		if (!backup_pos)
			continue;

		/* Verify the suffix is at the end of the filename */
		fname_len = strlen((char *)filename);
		if (backup_pos != ((char *)filename + fname_len - suffix_len)) {
			/* .v1_backup is not at the end, skip */
			continue;
		}

		printf("Found interrupted conversion backup: %s\n", filename);
		recovery_performed = 1;

		/* Construct full backup file path */
		plat_os_abs_memset(backup_fpath, 0, sizeof(backup_fpath));

		if (sizeof(backup_fpath) < (fname_len + PATH_OVERHEAD)) {
			printf("Error: Backup filepath too long, skipping: %s\n",
			       filename);
			continue;
		}

		available_space = sizeof(backup_fpath) - fname_len - PATH_OVERHEAD;

		/* Check for overflow: dirname + "/" + filename + null */
		if (dirname_len > available_space) {
			printf("Error: Backup filepath too long, skipping: %s\n",
			       filename);
			continue;
		}

		snprintf_ret = snprintf((char *)backup_fpath,
					sizeof(backup_fpath),
					"%s/%s",
					nvm_ctx->nvm_dname,
					filename);

		if (snprintf_ret < 0 || (size_t)snprintf_ret >= sizeof(backup_fpath)) {
			printf("Error: Failed to construct backup filepath for: %s\n",
			       filename);
			continue;
		}

		/* Extract original filename by removing .v1_backup suffix */
		plat_os_abs_memset(filepath, 0, sizeof(filepath));

		if (fname_len < suffix_len) {
			printf("Error: Invalid filename length\n");
			continue;
		}

		original_name_len = fname_len - suffix_len;

		if (sizeof(filepath) < (original_name_len + PATH_OVERHEAD)) {
			printf("Error: Original filepath too long, skipping: %s\n",
			       filename);
			continue;
		}

		available_space = sizeof(filepath) - original_name_len - PATH_OVERHEAD;

		/* Check for overflow: dirname + "/" + original_name + null */
		if (dirname_len > available_space) {
			printf("Error: Original filepath too long, skipping: %s\n",
			       filename);
			continue;
		}

		/* Build original filepath: directory + "/" + original_filename */
		snprintf_ret = snprintf((char *)filepath,
					sizeof(filepath),
					"%s/",
					nvm_ctx->nvm_dname);

		if (snprintf_ret < 0 || (size_t)snprintf_ret >= sizeof(filepath)) {
			printf("Error: Failed to construct filepath prefix for: %s\n",
			       filename);
			continue;
		}

		if (sizeof(filepath) < (size_t)snprintf_ret) {
			printf("Error: Invalid snprintf result\n");
			continue;
		}

		/* Calculate remaining space in filepath buffer */
		remaining_space = sizeof(filepath) - (size_t)snprintf_ret;

		/* Append original filename (without .v1_backup suffix) */
		if (original_name_len >= remaining_space) {
			printf("Error: Original filename too long, skipping: %s\n",
			       filename);
			continue;
		}

		strncat((char *)filepath, (char *)filename, original_name_len);

		printf("Restoring: %s -> %s\n", backup_fpath, filepath);

		/* Restore from backup */
		if (restore_blob_from_backup(nvm_ctx, filepath, backup_fpath) != 0) {
			printf("Warning: Failed to restore %s\n", filepath);
			/* Continue with other files */
		}

		/* Delete backup file after successful recovery */
		delete_blob_backup(nvm_ctx, backup_fpath);
	}

	/* Close directory */
	plat_os_abs_close_dir(dir_handle);

	if (recovery_performed) {
		printf("Recovery complete. All files reverted to V1 format.\n");
		printf("Conversion will be retried.\n\n");
	} else {
		printf("No interrupted conversion detected.\n\n");
	}

	return recovery_performed;
}

/* Convert chunk blobs (all blobs except master) */
static uint32_t convert_chunk_blobs(struct nvm_ctx_st *nvm_ctx,
				    uint8_t *master_filename,
				    uint8_t *master_filepath,
				    uint8_t *master_blob_found,
				    converted_files_list_t *converted_list,
				    uint32_t *files_converted)
{
	void *dir_handle = NULL;
	uint8_t *filename = NULL;
	uint8_t filepath[MAX_FNAME_DNAME_SZ * 2];
	uint8_t backup_fpath[MAX_FNAME_DNAME_SZ * 2];
	uint8_t is_master_blob = 0;
	uint32_t conversion_failed = 0;
	int snprintf_ret;
	size_t dirname_len;
	size_t fname_len;
	size_t available_space;

	if (!nvm_ctx || !master_filename || !master_filepath ||
	    !master_blob_found || !converted_list || !files_converted) {
		printf("Error: Invalid parameters for converting chunk blobs\n");
		return 1;
	}

	printf("\n=== Phase 1: Converting chunk blobs ===\n");

	/* Open directory containing NVM blobs */
	dir_handle = plat_os_abs_open_dir(nvm_ctx->nvm_dname);
	if (!dir_handle) {
		printf("Error: Failed to open directory %s\n", nvm_ctx->nvm_dname);
		return 1;
	}

	dirname_len = strlen((char *)nvm_ctx->nvm_dname);

	/* Loop through all files in directory */
	while ((filename = plat_os_abs_read_dir(dir_handle)) != NULL) {
		/* Skip files that shouldn't be processed */
		if (should_skip_file(filename))
			continue;

		/* Check if this is the master blob */
		is_master_blob = (strcmp((char *)filename,
					 (char *)master_filename) == 0) ? 1 : 0;

		if (is_master_blob) {
			/* Save master blob path for later conversion */
			fname_len = strlen((char *)filename);

			if ((MAX_FNAME_DNAME_SZ * 2) < (fname_len + PATH_OVERHEAD)) {
				printf("Error: Master filepath too long: %s\n",
				       filename);
				conversion_failed = 1;
				break;
			}

			available_space =
				(MAX_FNAME_DNAME_SZ * 2) - fname_len - PATH_OVERHEAD;

			/* Check for overflow: dirname + "/" + filename + null */
			if (dirname_len > available_space) {
				printf("Error: Master filepath too long: %s\n",
				       filename);
				conversion_failed = 1;
				break;
			}

			snprintf_ret = snprintf((char *)master_filepath,
						MAX_FNAME_DNAME_SZ * 2,
						"%s/%s",
						nvm_ctx->nvm_dname,
						filename);

			if (snprintf_ret < 0 ||
			    (size_t)snprintf_ret >= (MAX_FNAME_DNAME_SZ * 2)) {
				printf("Error: Failed to construct master filepath: %s\n",
				       filename);
				conversion_failed = 1;
				break;
			}

			*master_blob_found = 1;
			printf("Master blob found, will convert last: %s\n",
			       filename);
			continue; /* Skip master blob in first pass */
		}

		/* Construct file paths */
		plat_os_abs_memset(filepath, 0, sizeof(filepath));
		fname_len = strlen((char *)filename);

		if (sizeof(filepath) < (fname_len + PATH_OVERHEAD)) {
			printf("Error: Filepath too long, skipping: %s\n", filename);
			continue;
		}

		available_space = sizeof(filepath) - fname_len - PATH_OVERHEAD;

		/* Check for overflow: dirname + "/" + filename + null */
		if (dirname_len > available_space) {
			printf("Error: Filepath too long, skipping: %s\n",
			       filename);
			continue;
		}

		snprintf_ret = snprintf((char *)filepath,
					sizeof(filepath),
					"%s/%s",
					nvm_ctx->nvm_dname,
					filename);

		if (snprintf_ret < 0 || (size_t)snprintf_ret >= sizeof(filepath)) {
			printf("Error: Failed to construct filepath for: %s\n",
			       filename);
			continue;
		}

		plat_os_abs_memset(backup_fpath, 0, sizeof(backup_fpath));

		if (sizeof(backup_fpath) < (fname_len + BACKUP_PATH_OVERHEAD)) {
			printf("Error: Backup filepath too long, skipping: %s\n",
			       filename);
			continue;
		}

		available_space =
			sizeof(backup_fpath) - fname_len - BACKUP_PATH_OVERHEAD;

		/* Check for overflow: dirname + "/" + filename + ".v1_backup" + null */
		if (dirname_len > available_space) {
			printf("Error: Backup filepath too long, skipping: %s\n",
			       filename);
			continue;
		}

		snprintf_ret = snprintf((char *)backup_fpath,
					sizeof(backup_fpath),
					"%s/%s.v1_backup",
					nvm_ctx->nvm_dname,
					filename);

		if (snprintf_ret < 0 || (size_t)snprintf_ret >= sizeof(backup_fpath)) {
			printf("Error: Failed to construct backup filepath for: %s\n",
			       filename);
			continue;
		}

		printf("Converting chunk blob: %s\n", filename);

		if (convert_single_blob_file(nvm_ctx, filepath,
					     backup_fpath, 0) != 0) {
			conversion_failed = 1;
			break;
		}

		/* Add to converted list for potential rollback */
		if (add_to_converted_files_list(converted_list, filepath) != 0) {
			conversion_failed = 1;
			break;
		}

		printf("Successfully converted chunk blob: %s\n", filename);

		if (*files_converted >= UINT32_MAX) {
			printf("Error: Files converted counter would overflow\n");
			conversion_failed = 1;
			break;
		}
		(*files_converted)++;
	}

	plat_os_abs_close_dir(dir_handle);

	return conversion_failed;
}

static uint32_t convert_master_blob(struct nvm_ctx_st *nvm_ctx,
				    uint8_t *master_filename,
				    uint8_t *master_filepath,
				    converted_files_list_t *converted_list,
				    uint32_t *files_converted)
{
	uint8_t backup_fpath[MAX_FNAME_DNAME_SZ * 3];
	uint32_t conversion_failed = 0;
	int snprintf_ret;
	size_t dirname_len;
	size_t fname_len;
	size_t available_space;

	if (!nvm_ctx || !master_filename || !master_filepath ||
	    !converted_list || !files_converted) {
		printf("Error: Invalid parameters for converting master blob\n");
		return 1;
	}

	printf("\n=== Phase 2: Converting master blob ===\n");

	/* Construct backup file path for master blob */
	plat_os_abs_memset(backup_fpath, 0, sizeof(backup_fpath));

	dirname_len = strlen((char *)nvm_ctx->nvm_dname);
	fname_len = strlen((char *)master_filename);

	if (sizeof(backup_fpath) < (fname_len + BACKUP_PATH_OVERHEAD)) {
		printf("Error: Master backup filepath too long\n");
		return 1;
	}

	available_space = sizeof(backup_fpath) - fname_len - BACKUP_PATH_OVERHEAD;

	/* Check for overflow: dirname + "/" + filename + ".v1_backup" + null */
	if (dirname_len > available_space) {
		printf("Error: Master backup filepath too long\n");
		return 1;
	}

	snprintf_ret = snprintf((char *)backup_fpath,
				sizeof(backup_fpath),
				"%s/%s.v1_backup",
				nvm_ctx->nvm_dname,
				master_filename);

	if (snprintf_ret < 0 || (size_t)snprintf_ret >= sizeof(backup_fpath)) {
		printf("Error: Failed to construct master backup filepath\n");
		return 1;
	}

	printf("Converting master blob: %s\n", master_filename);

	/* Convert the master blob file (is_master_blob = 1) */
	if (convert_single_blob_file(nvm_ctx, master_filepath, backup_fpath, 1) != 0) {
		conversion_failed = 1;
	} else {
		/* Add to converted list for potential rollback */
		if (add_to_converted_files_list(converted_list, master_filepath) != 0) {
			conversion_failed = 1;
		} else {
			printf("Successfully converted master blob: %s\n",
			       master_filename);

			if (*files_converted >= UINT32_MAX) {
				printf("Error: Files converted counter would overflow\n");
				conversion_failed = 1;
			} else {
				(*files_converted)++;
			}
		}
	}

	return conversion_failed;
}

/* Main v1 to v2 conversion function */
static uint8_t nvm_blobs_convert_v1_to_v2(struct nvm_ctx_st *nvm_ctx)
{
	uint8_t master_filename[MAX_FNAME_DNAME_SZ] = {0};
	uint8_t master_filepath[MAX_FNAME_DNAME_SZ * 2] = {0};
	uint8_t master_blob_found = 0;
	uint32_t files_converted = 0;
	uint8_t conversion_failed = 0;
	uint8_t ret = 0;
	converted_files_list_t converted_list = {0};

	if (!nvm_ctx) {
		printf("Error: Invalid nvm_ctx\n");
		return 1;
	}

	printf("\nStarted NVM blobs conversion: v1 to v2.\n");

	/* First, check for and recover from any interrupted previous conversion */
	nvm_blobs_recover_from_interrupted_conversion(nvm_ctx);

	/* Initialize converted files list */
	if (init_converted_files_list(&converted_list, CONVERTED_FILES_INITIAL_CAPACITY))
		return 1;

	/* Extract master filename */
	extract_master_filename(nvm_ctx, master_filename, sizeof(master_filename));

	/* Phase 1: Convert all chunk blobs (skip master) */
	conversion_failed = convert_chunk_blobs(nvm_ctx,
						master_filename,
						master_filepath,
						&master_blob_found,
						&converted_list,
						&files_converted);

	/* Phase 2: Convert master blob if all chunks succeeded */
	if (!conversion_failed && master_blob_found) {
		conversion_failed = convert_master_blob(nvm_ctx,
							master_filename,
							master_filepath,
							&converted_list,
							&files_converted);
	}

	/* Handle rollback or cleanup */
	if (conversion_failed) {
		rollback_converted_blobs(nvm_ctx, &converted_list);
		ret = 1;
	} else {
		printf("\nv1 to v2 conversion successful: %u files converted\n",
		       files_converted);
		cleanup_backup_files(nvm_ctx, &converted_list);
		ret = 0;
	}

	/* Free the converted files list */
	free_converted_files_list(&converted_list);

	return ret;
}

/* Perform blob format conversion */
uint8_t nvm_blobs_format_conversion(struct nvm_ctx_st *nvm_ctx,
				    uint8_t current_version,
				    uint8_t target_version)
{
	uint8_t ret = 1;

	if (!nvm_ctx) {
		printf("Error: Invalid nvm_ctx\n");
		return 1;
	}

	switch (current_version) {
	case NVM_HEADER_SZ_V1:
		if (target_version == NVM_HEADER_SZ_V2)
			ret = nvm_blobs_convert_v1_to_v2(nvm_ctx);
		else
			printf("\nBlob conversion: unsupported target version\n");

		break;
	default:
		printf("\nBlob conversion: invalid format version input\n");
	}

	return ret;
}
#endif
