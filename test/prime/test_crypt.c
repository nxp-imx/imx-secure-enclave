// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "internal/prime_info.h"
#include "internal/prime_service.h"
#include "internal/v2x_version.h"

#include "include/test_prime.h"
#include "include/test_prime_utils.h"

#define SIZE_16MB  0x01000000
#define SIZE_32MB  0x02000000
#define SIZE_64MB  0x04000000
#define SIZE_128MB 0x08000000
#define SIZE_256MB 0x10000000

#ifndef MAP_HUGETLB
#  define MAP_HUGETLB 0x40000
#endif
#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif

#ifndef MAP_HUGE_32MB
#define MAP_HUGE_32MB (25U << MAP_HUGE_SHIFT)  // log2(32MB)=25
#endif

#define PAGEMAP_ENTRY_SIZE	8
#define PAGEMAP_PRESENT_BIT	63
#define PAGEMAP_PFN_MASK	55

static open_service_args_t op_serv_args[6] = {0};

void hexdump(uint8_t buf[], uint32_t size)
{
	int i = 0;

	for (; i < size; i++) {
		if ((i % 16) == 0)
			printf("\n");
		printf("%x ", buf[i]);
	}
	printf("\n");
}

static void dump_test_params(open_service_args_t *args)
{
#ifdef DEBUG
	printf("VA = 0x%lx\n", args->virtual_addr);
	printf("PA = 0x%012" PRIx64 "\n", args->physical_addr);
	printf("size 0x%x\n", args->size);
#endif
}

static uint64_t virt_to_phys(void *va)
{
	int fd = open("/proc/self/pagemap", O_RDONLY);

	if (fd < 0)
		return 0;

	long pagesize = sysconf(_SC_PAGESIZE);
	uint64_t vpn = (uint64_t)va / pagesize;

	if (lseek(fd, vpn * PAGEMAP_ENTRY_SIZE, SEEK_SET) == (off_t)-1) {
		close(fd); return 0;
	}

	uint64_t entry = 0;

	if (read(fd, &entry, PAGEMAP_ENTRY_SIZE) != PAGEMAP_ENTRY_SIZE) {
		close(fd);
		return 0;
	}

	close(fd);

	if (!(entry & (1ULL << PAGEMAP_PRESENT_BIT)))
		return 0;   // present bit

	uint64_t pfn = entry & ((1ULL << PAGEMAP_PFN_MASK) - 1);

	return (pfn * pagesize);
}

void *alloc_huge(size_t size, int huge_flag, uint64_t *phys_out)
{
	void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS |
			MAP_HUGETLB | huge_flag, -1, 0);

	if (addr == MAP_FAILED) {
		perror("HugeTLB mmap failed");
		return NULL;
	}

	memset(addr, 0xAA, size);  // force allocation

	uint64_t pa = virt_to_phys(addr);

	if (pa == 0) {
		fprintf(stderr, "Failed to read physical address\n");
		munmap(addr, size);
		return NULL;
	}

	*phys_out = pa;
	return addr;
}

/*
 * Return the physical address of the n-th sub-page of a HugeTLB mapping.
 * Each sub-page is page_size bytes. Virtual addresses are contiguous but
 * physical addresses of individual hugepages are NOT guaranteed contiguous.
 * Must call virt_to_phys() per sub-page to get the correct PA.
 */
static uint64_t get_subpage_phys(void *base_va, uint32_t idx, size_t page_size)
{
	return virt_to_phys((uint8_t *)base_va + (uint64_t)idx * page_size);
}

static void test_keyslot(void)
{
	prime_hdl_t serv_hdl;

	op_serv_args[0].serv_type = SERVICE_TYPE_ALL;
	op_serv_args[0].size  = SIZE_256MB;
	if (prime_open_service(&op_serv_args[0], &serv_hdl)) {
		printf("Failed to open prime service\n");
		return;
	}

	if (test_hmac_keyslot(serv_hdl))
		printf("HMAC Keyslot test failed\n");

	if (test_aes_keyslot(serv_hdl))
		printf("AES Keyslot test failed\n");

	prime_close_service(op_serv_args[0].service_hdl);
}

static void test_prime_info(void)
{
	prime_hdl_t serv_hdl;
	prime_info_t prime_info;
	v2x_version_t v2x_version;

	get_v2x_version(&v2x_version);

	printf("V2X version : %d.%d.%d\nCommit Id : 0x%x\n",
	       v2x_version.major, v2x_version.minor,
	       v2x_version.patch, v2x_version.commit_id);

	op_serv_args[0].serv_type = SERVICE_TYPE_ALL;
	op_serv_args[0].size  = SIZE_256MB;
	if (prime_open_service(&op_serv_args[0], &serv_hdl)) {
		printf("Failed to open prime service\n");
		return;
	}

	if (!prime_get_info(serv_hdl, &prime_info))
		printf("PRIME API version : %d.%d.%d\nNumber of FIFO entries : %d\n",
		       prime_info.major, prime_info.minor, prime_info.patch,
		       prime_info.num_fifo_entries);

	prime_close_service(op_serv_args[0].service_hdl);
}

static int execute_crypto_test(uint32_t serv_hdl, void *va, uint64_t phys)
{
	if (hmac_test(serv_hdl, va, phys))
		return -1;
	if (aes_cbc_test(serv_hdl, va, phys))
		return -1;
	if (aes_ecb_test(serv_hdl, va, phys))
		return -1;
	if (aes_ctr_test(serv_hdl, va, phys))
		return -1;
	if (aes_gcm_test(serv_hdl, va, phys))
		return -1;
	if (hash_one_go_test(serv_hdl, va, phys))
		return -1;

	return 0;
}

static int test_32MB_memory(void *va, uint64_t phys, size_t size)
{
	prime_hdl_t serv_hdl;
	int32_t err;

	printf("\nExecuting %s\n", __func__);
#ifdef DEBUG
	printf("VA = %p\n", va);
	printf("PA = 0x%012" PRIx64 "\n", phys);
	printf("size 0x%lx\n", size);
	printf("Aligned? %s\n", (phys % size == 0 ? "YES" : "NO"));
#endif
	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	op_serv_args[0].serv_type = SERVICE_TYPE_ALL;
	op_serv_args[0].physical_addr = phys;
	op_serv_args[0].size  = size;
	err = prime_open_service(&op_serv_args[0], &serv_hdl);

	if (err) {
		printf("Failed to open prime service\n");
		return err;
	}

	if (hmac_test(serv_hdl, va, phys)) {
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}
	printf("SHA2-256-HMAC test passed\n");

	if (aes_cbc_test(serv_hdl, va, phys)) {
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}
	printf("AES-256-CBC test passed\n");

	if (aes_ecb_test(serv_hdl, va, phys)) {
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}
	printf("AES-256-ECB test passed\n");

	if (aes_ctr_test(serv_hdl, va, phys)) {
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}
	printf("AES-256-CTR (8192B) and (256B) test passed\n");

	if (aes_gcm_test(serv_hdl, va, phys)) {
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}
	printf("AES-256-GCM(256B) test passed\n");

	if (hash_one_go_test(serv_hdl, va, phys))
		return -1;

	printf("Hash One Go (SHA2-256/384/512) tests passed\n");

	prime_close_service(op_serv_args[0].service_hdl);

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_32MB_4_session(void *va, uint64_t phys, size_t size)
{
	prime_hdl_t serv_hdl;
	void *temp_va;
	uint64_t temp_phys;
	int32_t err, i;

	/*
	 * Open 4 sessions of SIZE_32MB each, one per 32MB HugeTLB sub-page.
	 * Use get_subpage_phys() per iteration: MAP_HUGE_32MB pages are NOT
	 * guaranteed physically contiguous, so PA[i] != PA[0] + i*SIZE_32MB.
	 * Close current session on any error before returning.
	 */
	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	memset(va, 0, SIZE_256MB);
	printf("\nExecuting %s\n", __func__);
	for (i = 0; i < 4; i++) {
		temp_va   = (uint8_t *)va + (uint64_t)i * SIZE_32MB;
		temp_phys = get_subpage_phys(va, i, SIZE_32MB);
		if (!temp_phys) {
			printf("Failed to get PA for sub-page %d\n", i);
			return -1;
		}
#ifdef DEBUG
		printf("VA = %p\n", temp_va);
		printf("PA = 0x%012" PRIx64 "\n", temp_phys);
		printf("Aligned? %s\n", (temp_phys % SIZE_32MB == 0 ? "YES" : "NO"));
#endif
		op_serv_args[i].serv_type     = SERVICE_TYPE_ALL;
		op_serv_args[i].physical_addr = temp_phys;
		op_serv_args[i].size          = SIZE_32MB;
		err = prime_open_service(&op_serv_args[i], &serv_hdl);

		if (err) {
			printf("Failed to open %dth prime service\n", i);
			return err;
		}
		if (execute_crypto_test(serv_hdl, temp_va, temp_phys)) {
			prime_close_service(op_serv_args[i].service_hdl);
			return -1;
		}

		prime_close_service(op_serv_args[i].service_hdl);
	}

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_32MB_4_session_close_in_end(void *va, uint64_t phys, size_t size)
{
	prime_hdl_t serv_hdl;
	void *temp_va;
	uint64_t temp_phys;
	int32_t err, i;

	/*
	 * Open 4 sessions of SIZE_32MB each (all open concurrently), then
	 * close all together. Use get_subpage_phys() per sub-page for correct PA.
	 * goto cleanup ensures all open sessions are closed on any error path.
	 */
	printf("\nExecuting %s\n", __func__);
	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	memset(va, 0, SIZE_256MB);
	for (i = 0; i < 4; i++) {
		temp_va   = (uint8_t *)va + (uint64_t)i * SIZE_32MB;
		temp_phys = get_subpage_phys(va, i, SIZE_32MB);
		if (!temp_phys) {
			printf("Failed to get PA for sub-page %d\n", i);
			goto cleanup;
		}
#ifdef DEBUG
		printf("VA = %p\n", temp_va);
		printf("PA = 0x%012" PRIx64 "\n", temp_phys);
		printf("Aligned? %s\n", (temp_phys % SIZE_32MB == 0 ? "YES" : "NO"));
#endif
		op_serv_args[i].serv_type     = SERVICE_TYPE_ALL;
		op_serv_args[i].physical_addr = temp_phys;
		op_serv_args[i].size          = SIZE_32MB;
		err = prime_open_service(&op_serv_args[i], &serv_hdl);

		if (err) {
			printf("%dth prime service open failed : FAILURE\n", i);
			goto cleanup;
		}
		if (execute_crypto_test(serv_hdl, temp_va, temp_phys))
			goto cleanup;
	}

	printf("%s completed successfully\n", __func__);
	for (i = 0; i < 4; i++) {
		if (op_serv_args[i].service_hdl > 0)
			prime_close_service(op_serv_args[i].service_hdl);
	}
	return 0;

cleanup:
	for (i = 0; i < 4; i++) {
		if (op_serv_args[i].service_hdl > 0)
			prime_close_service(op_serv_args[i].service_hdl);
	}
	return -1;
}

static int test_in_range_addr(void *va, uint64_t phys, size_t size)
{
	prime_hdl_t serv_hdl;
	void *temp_va;
	uint64_t base_phys;
	uint64_t temp_phys;
	int32_t err;

	/*
	 * Open a SIZE_32MB session at sub-page 0, then open a SIZE_16MB
	 * sub-session at +16MB within the same 32MB page. The sub-session
	 * PA (phys+16MB) falls inside the existing ATU window, so the driver
	 * returns EEXIST and provides the mapped inbound offset directly.
	 * Use get_subpage_phys() for the base PA of sub-page 0.
	 * All error paths close open sessions before returning.
	 */
	printf("\nExecuting %s\n", __func__);
	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	memset(va, 0, SIZE_256MB);

	base_phys = get_subpage_phys(va, 0, SIZE_32MB);
	if (!base_phys) {
		printf("Failed to get PA for sub-page 0\n");
		return -1;
	}

	op_serv_args[0].serv_type     = SERVICE_TYPE_ALL;
	op_serv_args[0].physical_addr = base_phys;
	op_serv_args[0].size          = size;
	err = prime_open_service(&op_serv_args[0], &serv_hdl);

	if (err) {
		printf("Failed to open prime service\n");
		return err;
	}

	if (execute_crypto_test(serv_hdl, va, base_phys)) {
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}

	/* sub-window at +16MB inside the 32MB mapped window */
	temp_va   = (uint8_t *)va + SIZE_16MB;
	temp_phys = base_phys + SIZE_16MB;
#ifdef DEBUG
	printf("VA = %p\n", temp_va);
	printf("PA = 0x%012" PRIx64 "\n", temp_phys);
	printf("Aligned? %s\n", (temp_phys % SIZE_16MB == 0 ? "YES" : "NO"));
#endif
	op_serv_args[1].serv_type     = SERVICE_TYPE_ALL;
	op_serv_args[1].physical_addr = temp_phys;
	op_serv_args[1].size          = SIZE_16MB;
	err = prime_open_service(&op_serv_args[1], &serv_hdl);

	if (err) {
		printf("Failed to open intermediate prime service\n");
		prime_close_service(op_serv_args[0].service_hdl);
		return err;
	}

	if (execute_crypto_test(serv_hdl, temp_va, temp_phys)) {
		prime_close_service(op_serv_args[1].service_hdl);
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}

#ifdef SE_NEG_TEST
	prime_close_service(op_serv_args[1].service_hdl); /* must not unmap ATU */
	op_serv_args[1].service_hdl = 0;
#endif
	if (op_serv_args[1].service_hdl > 0)
		prime_close_service(op_serv_args[1].service_hdl); /* it must pass */
	prime_close_service(op_serv_args[0].service_hdl);

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_out_of_range_addr(void *va, uint64_t phys, size_t size)
{
	prime_hdl_t serv_hdl;
	void *temp_va;
	uint64_t temp_phys;
	uint64_t base_phys;
	int32_t err;

	/*
	 * Open a SIZE_32MB session at sub-page 0, then attempt to open a
	 * session at sub-page 1 (a different 32MB hugepage, physically
	 * non-contiguous with sub-page 0). Sub-page 1 PA is outside the
	 * ATU window mapped for sub-page 0, so the driver must reject it.
	 * Use get_subpage_phys() for both PAs to get correct values.
	 * All error paths close open sessions before returning.
	 */
	printf("\nExecuting %s\n", __func__);
	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	memset(va, 0, SIZE_256MB);

	base_phys = get_subpage_phys(va, 0, SIZE_32MB);
	if (!base_phys) {
		printf("Failed to get PA for sub-page 0\n");
		return -1;
	}

	op_serv_args[0].serv_type     = SERVICE_TYPE_ALL;
	op_serv_args[0].physical_addr = base_phys;
	op_serv_args[0].size          = size;
	err = prime_open_service(&op_serv_args[0], &serv_hdl);
	if (err) {
		printf("Failed to open prime service\n");
		return err;
	}

	if (execute_crypto_test(serv_hdl, va, base_phys)) {
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}

	/* OOB: sub-page 1 is a separate hugepage, outside window of sub-page 0 */
	temp_va   = (uint8_t *)va + SIZE_32MB;
	temp_phys = get_subpage_phys(va, 1, SIZE_32MB);
	if (!temp_phys) {
		printf("Failed to get PA for sub-page 1\n");
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}
#ifdef DEBUG
	printf("VA = %p\n", temp_va);
	printf("PA = 0x%012" PRIx64 "\n", temp_phys);
	printf("Aligned? %s\n", (temp_phys % SIZE_32MB == 0 ? "YES" : "NO"));
#endif
	op_serv_args[1].serv_type     = SERVICE_TYPE_ALL;
	op_serv_args[1].physical_addr = temp_phys;
	op_serv_args[1].size          = SIZE_32MB;
	err = prime_open_service(&op_serv_args[1], &serv_hdl);

	if (err) {
		printf("Failure expected for unauthorized address : SUCCESS\n");
		op_serv_args[1].service_hdl = 0;
	} else {
		/* unexpected success — close to prevent leak */
		prime_close_service(op_serv_args[1].service_hdl);
		op_serv_args[1].service_hdl = 0;
	}

	prime_close_service(op_serv_args[0].service_hdl);

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_user_alloc_flow(void)
{
	int32_t err;
	uint64_t phys;
	/*
	 * Allocate 8x32MB = 256MB total using MAP_HUGE_32MB (ARM64 CONT_PMD,
	 * valid on 4KB base pages). alloc_size covers all sub-test strides.
	 * Each prime_open_service() uses win_size=SIZE_32MB (one page) to
	 * satisfy ATU constraint: outbound_addr must be aligned to win_size,
	 * and MAP_HUGE_32MB only guarantees 32MB alignment.
	 * goto out ensures munmap is always called even on sub-test failure.
	 */
	size_t alloc_size = SIZE_256MB;
	size_t size = SIZE_32MB;         /* one 32MB page per ATU window */
	int flag = MAP_HUGE_32MB;
	void *va = alloc_huge(alloc_size, flag, &phys);

	if (!va)
		return 1;

	err = test_32MB_memory(va, phys, size);
	if (err)
		goto out;

	err = test_32MB_4_session(va, phys, size);
	if (err)
		goto out;

	err = test_32MB_4_session_close_in_end(va, phys, size);
	if (err)
		goto out;

	err = test_in_range_addr(va, phys, size);
	if (err)
		goto out;

	err = test_out_of_range_addr(va, phys, size);

out:
	munmap(va, alloc_size);
	return err;
}

static int test_se_256MB_memory(void)
{
	prime_hdl_t serv_hdl;
	int32_t err;

	printf("\nExecuting %s\n", __func__);

	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	op_serv_args[0].serv_type = SERVICE_TYPE_ALL;
	op_serv_args[0].size  = SIZE_256MB;
	err = prime_open_service(&op_serv_args[0], &serv_hdl);

	if (err) {
		printf("Failed to open prime service\n");
		return err;
	}

	dump_test_params(&op_serv_args[0]);

	if (hmac_test(serv_hdl, (void *)op_serv_args[0].virtual_addr,
		      op_serv_args[0].physical_addr)) {
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}
	printf("SHA2-256-HMAC test passed\n");

	if (aes_cbc_test(serv_hdl, (void *)op_serv_args[0].virtual_addr,
			 op_serv_args[0].physical_addr)) {
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}
	printf("AES-256-CBC test passed\n");

	if (aes_ecb_test(serv_hdl, (void *)op_serv_args[0].virtual_addr,
			 op_serv_args[0].physical_addr)) {
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}
	printf("AES-256-ECB test passed\n");

	if (aes_ctr_test(serv_hdl, (void *)op_serv_args[0].virtual_addr,
			 op_serv_args[0].physical_addr)) {
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}
	printf("AES-256-CTR (8192B) and (256B) test passed\n");

	if (aes_gcm_test(serv_hdl, (void *)op_serv_args[0].virtual_addr,
			 op_serv_args[0].physical_addr)) {
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}
	printf("AES-256-GCM(256B) test passed\n");

	if (hash_one_go_test(serv_hdl, (void *)op_serv_args[0].virtual_addr,
			     op_serv_args[0].physical_addr))
		return -1;

	prime_close_service(op_serv_args[0].service_hdl);

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_se_64MB_6_reqs(void)
{
	prime_hdl_t serv_hdl;
	int32_t err, i;

	printf("\nExecuting %s\n", __func__);

	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	for (i = 0; i < 6; i++) {
		op_serv_args[i].serv_type = SERVICE_TYPE_ALL;
		op_serv_args[i].size  = SIZE_64MB;
		err = prime_open_service(&op_serv_args[i], &serv_hdl);

		if (err) {
			printf("Failed to open prime service\n");
			return err;
		}

		dump_test_params(&op_serv_args[i]);

		if (execute_crypto_test(serv_hdl, (void *)op_serv_args[i].virtual_addr,
					op_serv_args[i].physical_addr)) {
			prime_close_service(op_serv_args[i].service_hdl);
			return -1;
		}

		prime_close_service(op_serv_args[i].service_hdl);
	}

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_se_64MB_4_reqs_again_64MB_2_reqs(void)
{
	prime_hdl_t serv_hdl;
	int32_t err, i;

	printf("\nExecuting %s\n", __func__);

	/*
	 * 4x64MB concurrent (= 256MB pool fully utilized), free [1] and [3],
	 * reopen [1] and [3] as 64MB each.
	 * goto cleanup_4 ensures all open sessions are closed on any error path.
	 * service_hdl zeroed after explicit close to prevent double-free in cleanup.
	 */
	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	for (i = 0; i < 4; i++) {
		op_serv_args[i].serv_type = SERVICE_TYPE_ALL;
		op_serv_args[i].size  = SIZE_64MB;
		err = prime_open_service(&op_serv_args[i], &serv_hdl);

		if (err) {
			printf("Failed to open prime service\n");
			goto cleanup_4;
		}

		dump_test_params(&op_serv_args[i]);

		if (execute_crypto_test(serv_hdl, (void *)op_serv_args[i].virtual_addr,
					op_serv_args[i].physical_addr))
			goto cleanup_4;
	}

	prime_close_service(op_serv_args[1].service_hdl);
	op_serv_args[1].service_hdl = 0;
	prime_close_service(op_serv_args[3].service_hdl);
	op_serv_args[3].service_hdl = 0;

	for (i = 1; i < 4; i += 2) {
		op_serv_args[i].serv_type     = SERVICE_TYPE_ALL;
		op_serv_args[i].size          = SIZE_64MB;
		op_serv_args[i].virtual_addr  = 0;
		op_serv_args[i].physical_addr = 0;
		err = prime_open_service(&op_serv_args[i], &serv_hdl);

		if (err) {
			printf("Failed to open prime service\n");
			goto cleanup_4;
		}

		dump_test_params(&op_serv_args[i]);

		if (execute_crypto_test(serv_hdl, (void *)op_serv_args[i].virtual_addr,
					op_serv_args[i].physical_addr))
			goto cleanup_4;
	}

	for (i = 0; i < 4; i++)
		prime_close_service(op_serv_args[i].service_hdl);

	printf("%s completed successfully\n", __func__);
	return 0;

cleanup_4:
	for (i = 0; i < 4; i++) {
		if (op_serv_args[i].service_hdl > 0)
			prime_close_service(op_serv_args[i].service_hdl);
	}
	return -1;
}

static int test_se_64MB_4_reqs_128MB_neg(void)
{
	prime_hdl_t serv_hdl;
	int32_t err, i;

	printf("\nExecuting %s\n", __func__);

	/*
	 * 4x64MB concurrent (= 256MB pool fully utilized), free [1] and [3]
	 * (non-adjacent slots), attempt 128MB which must fail: only two
	 * non-contiguous 64MB slots are free, no 128MB contiguous block
	 * available.
	 * goto cleanup_neg ensures all open sessions are closed on any error path.
	 * service_hdl zeroed after explicit close to prevent double-free in cleanup.
	 */
	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	for (i = 0; i < 4; i++) {
		op_serv_args[i].serv_type = SERVICE_TYPE_ALL;
		op_serv_args[i].size  = SIZE_64MB;
		err = prime_open_service(&op_serv_args[i], &serv_hdl);

		if (err) {
			printf("Failed to open prime service\n");
			goto cleanup_neg;
		}

		dump_test_params(&op_serv_args[i]);

		if (execute_crypto_test(serv_hdl, (void *)op_serv_args[i].virtual_addr,
					op_serv_args[i].physical_addr))
			goto cleanup_neg;
	}

	prime_close_service(op_serv_args[1].service_hdl);
	op_serv_args[1].service_hdl = 0;
	prime_close_service(op_serv_args[3].service_hdl);
	op_serv_args[3].service_hdl = 0;

	op_serv_args[1].serv_type     = SERVICE_TYPE_ALL;
	op_serv_args[1].size          = SIZE_128MB;
	op_serv_args[1].virtual_addr  = 0;
	op_serv_args[1].physical_addr = 0;
	err = prime_open_service(&op_serv_args[1], &serv_hdl);

	if (err) {
		printf("Failure expected as no contiguous memory of 128 MB: SUCCESS\n");
		op_serv_args[1].service_hdl = 0;
	} else {
		prime_close_service(op_serv_args[1].service_hdl);
		op_serv_args[1].service_hdl = 0;
	}

	/* close [0] and [2]; [1] and [3] already freed */
	for (i = 0; i < 4; i += 2)
		prime_close_service(op_serv_args[i].service_hdl);

	printf("%s completed successfully\n", __func__);
	return 0;

cleanup_neg:
	for (i = 0; i < 4; i++) {
		if (op_serv_args[i].service_hdl > 0)
			prime_close_service(op_serv_args[i].service_hdl);
	}
	return -1;
}

static int test_se_64MB_4_reqs_128MB_pos(void)
{
	prime_hdl_t serv_hdl;
	int32_t err, i;

	printf("\nExecuting %s\n", __func__);

	/*
	 * 4x64MB concurrent (= 256MB pool fully utilized), free [1] and [2]
	 * (adjacent slots), attempt 128MB which must succeed: two adjacent
	 * 64MB slots form a contiguous 128MB block.
	 * goto cleanup_pos ensures all open sessions are closed on any error path.
	 * service_hdl zeroed after explicit close to prevent double-free in cleanup.
	 */
	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	for (i = 0; i < 4; i++) {
		op_serv_args[i].serv_type = SERVICE_TYPE_ALL;
		op_serv_args[i].size  = SIZE_64MB;
		err = prime_open_service(&op_serv_args[i], &serv_hdl);

		if (err) {
			printf("Failed to open prime service\n");
			goto cleanup_pos;
		}

		dump_test_params(&op_serv_args[i]);

		if (execute_crypto_test(serv_hdl, (void *)op_serv_args[i].virtual_addr,
					op_serv_args[i].physical_addr))
			goto cleanup_pos;
	}

	prime_close_service(op_serv_args[1].service_hdl);
	op_serv_args[1].service_hdl = 0;
	prime_close_service(op_serv_args[2].service_hdl);
	op_serv_args[2].service_hdl = 0;

	op_serv_args[1].serv_type     = SERVICE_TYPE_ALL;
	op_serv_args[1].size          = SIZE_128MB;
	op_serv_args[1].virtual_addr  = 0;
	op_serv_args[1].physical_addr = 0;
	err = prime_open_service(&op_serv_args[1], &serv_hdl);

	if (err) {
		printf("Open service fail for 128MB request\n");
		goto cleanup_pos;
	}

	dump_test_params(&op_serv_args[1]);

	if (execute_crypto_test(serv_hdl, (void *)op_serv_args[1].virtual_addr,
				op_serv_args[1].physical_addr))
		goto cleanup_pos;

	/* close [0],[1(128MB)],[3]; [2] already freed */
	for (i = 0; i < 4; i++) {
		if (i == 2)
			continue;
		prime_close_service(op_serv_args[i].service_hdl);
	}

	printf("%s completed successfully\n", __func__);
	return 0;

cleanup_pos:
	for (i = 0; i < 4; i++) {
		if (op_serv_args[i].service_hdl > 0)
			prime_close_service(op_serv_args[i].service_hdl);
	}
	return -1;
}

#ifdef SE_NEG_TEST
static int test_se_oob(void)
{
	prime_hdl_t serv_hdl;
	int32_t err;

	printf("\nExecuting %s\n", __func__);

	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	op_serv_args[0].serv_type = SERVICE_TYPE_ALL;
	op_serv_args[0].size  = SIZE_256MB;
	err = prime_open_service(&op_serv_args[0], &serv_hdl);

	if (err) {
		printf("Failed to open prime service\n");
		return err;
	}

	dump_test_params(&op_serv_args[0]);

	if (execute_crypto_test(serv_hdl, (void *)op_serv_args[0].virtual_addr,
				op_serv_args[0].physical_addr)) {
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}

	op_serv_args[0].virtual_addr += SIZE_256MB;

	if (execute_crypto_test(serv_hdl, (void *)op_serv_args[0].virtual_addr,
				op_serv_args[0].physical_addr)) {
		prime_close_service(op_serv_args[0].service_hdl);
		return -1;
	}

	prime_close_service(op_serv_args[0].service_hdl);

	printf("%s completed successfully\n", __func__);
	return 0;
}
#endif

static int test_se_alloc_flow(void)
{
	int32_t err;

	err = test_se_256MB_memory();
	if (err)
		return err;

	err = test_se_64MB_6_reqs();
	if (err)
		return err;

	err = test_se_64MB_4_reqs_again_64MB_2_reqs();
	if (err)
		return err;

	err = test_se_64MB_4_reqs_128MB_neg();
	if (err)
		return err;

	err = test_se_64MB_4_reqs_128MB_pos();
	if (err)
		return err;

#ifdef SE_NEG_TEST
	err = test_se_oob();
	if (err)
		return err;
#endif
	return err;
}

int main(void)
{
	int ret;

	test_prime_info();

	test_keyslot();

	printf("\n---------------- USER ALLOCATED MEMORY TEST --------------\n");
	ret = test_user_alloc_flow();
	if (ret)
		printf("------------ USER ALLOCATED MEMORY TEST FAILED -----------\n");
	else
		printf("------------ USER ALLOCATED MEMORY TEST PASSED -----------\n");

	printf("\n---------------- SE ALLOCATED MEMORY TEST ----------------\n");
	ret = test_se_alloc_flow();
	if (ret)
		printf("------------- SE ALLOCATED MEMORY TEST FAILED ------------\n");
	else
		printf("------------- SE ALLOCATED MEMORY TEST PASSED ------------\n");

	return ret;
}
