// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2026 NXP
 */

#include <errno.h>
#include <dirent.h>
#include <time.h>

#include "slt_log.h"
#include "shx_reader.h"
#include "hsm_exec.h"

#define DEFAULT_V2X_HSM_TV_DIR  "/usr/share/se/v2x_hsm_test_vectors"
#define DEFAULT_V2X_HSM_TV_FEXTN ".shx"

hsm_test_struct_t testCtx[20] = { 0 };

int isdir(const char *name)
{
	DIR *dir = opendir(name);

	if (dir) {
		closedir(dir);
		return 1;
	} else {
		return 0;
	}
}

// return 0 if file extension matches expected extension
static uint32_t extn_match(char *fname, char *exp_extn)
{
	char *file_extn = strrchr(fname, '.');

	if (file_extn == fname || !file_extn)
		return 1;

	// compare file extensions
	if (strcmp(file_extn, exp_extn) == 0)
		return 0;
}

void execute_test_vectors(FILE *fp)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	uint16_t i;
	uint32_t fails = 0;

	while ((read = getline(&line, &len, fp)) != -1) {
		if (line[0] == '<') {
			slt_print(SLT_DEBUG, "%s", line);
		} else {
			uint32_t these_fails = 0;

			for (i = 0;
			     i < (sizeof(tests) / sizeof(struct test_entry_t));
			     i++) {
				if (memcmp(line,
					   tests[i].name,
					   strlen(tests[i].name)) == 0) {
					slt_print(SLT_INFO, "test: %s", line);
					these_fails += hsm_exec_function(i, fp, testCtx);
					slt_print(SLT_INFO, "\n");
					break;
				}
			}
			fails += these_fails;
			if (these_fails != 0) {
				slt_print(SLT_ERROR,
					  "--- Test reported fails: %d\n", these_fails);
			}
		}
	}

	if (line) {
		free(line);
		line = NULL;
	}
}

/* Test entry function. */
int shx_v2x_hsm_tests(int argc, char *argv[])
{
	FILE *fp;

	uint32_t idx = 1;

	while (idx < argc) {
		do {
			fp = fopen(argv[idx], "r");
			if (!fp) {
				slt_print(SLT_ERROR,
					  "Can't open file: %s  --> FAIL\n", argv[idx]);
				break;
			}

			/* Indicate the start of a test */
			slt_print(SLT_NOTICE, "\n<test>\n");

			slt_print(SLT_NOTICE, "<filename>%s</filename>\n", argv[idx]);

			execute_test_vectors(fp);

		} while (false);

		idx++;

		if (fp) {
			(void)fclose(fp);

			/* Indicate the end of a test */
			slt_print(SLT_NOTICE, "\n</test>\n");
		}
	}

	return 0;
}

void ProcessDirectory(char *dir_name)
{
	struct dirent *dir_data;
	DIR *dir_p;
	char *fpath;
	uint32_t fpath_len;
	FILE *fp;

	struct dirent **namelist;
	int n = 0, i = 0;

	n = scandir(dir_name, &namelist, NULL, alphasort);
	if (n < 0) {
		printf("Failed to scan dir %s\n", dir_name);
	} else {
		for (i = 0; i < n; i++) {
			if (!strcmp(namelist[i]->d_name, "..") ||
			    !strcmp(namelist[i]->d_name, "."))
				continue;

			/* 2 is added for terminating NULL and file separator (/) */
			fpath_len = strlen(dir_name) + strlen(namelist[i]->d_name) + 2;

			fpath = (char *)malloc(fpath_len);

			snprintf(fpath, fpath_len, "%s/%s",
				 dir_name, namelist[i]->d_name);

			if (isdir(fpath)) {
				ProcessDirectory(fpath);
			} else {
				if (extn_match(namelist[i]->d_name,
					       DEFAULT_V2X_HSM_TV_FEXTN) == 0) {
					fp = fopen(fpath, "r");
					if (fp) {
						/* Indicate the start of a test */
						slt_print(SLT_NOTICE, "\n<test>\n");
						slt_print(SLT_NOTICE,
							  "<file>%s</file>\n", fpath);

						execute_test_vectors(fp);
						fclose(fp);
					} else {
						slt_print(SLT_ERROR,
							  "Can't open file:%s --> FAIL\n",
							  fpath);
					}
				}
			}

			if (fpath)
				free(fpath);

			free(namelist[i]);
		}
		free(namelist);
	}
}

/* Function to execute all TVs available in export/usr/share/se/she_test_vectors/ */
void shx_tests_run(void)
{
	ProcessDirectory(DEFAULT_V2X_HSM_TV_DIR);
}
