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
#include "internal/prime_service.h"

#include "include/test_prime.h"
#include "include/test_prime_utils.h"

#define SIZE_256MB 0x10000000
#define SIZE_512MB 0x20000000
#define SIZE_1GB   0x40000000

#ifndef MAP_HUGETLB
#  define MAP_HUGETLB 0x40000
#endif
#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif

#ifndef MAP_HUGE_32MB
#define MAP_HUGE_32MB (25U << MAP_HUGE_SHIFT)  // log2(32MB)=25
#endif

#ifndef MAP_HUGE_256MB
#define MAP_HUGE_256MB (28U << MAP_HUGE_SHIFT)  // log2(256MB)=28
#endif

#ifndef MAP_HUGE_1GB
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)  // 2^30 = 1 GiB
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

void data_cache_clean(uint8_t *buf, uint32_t len, int clean_only)
{
	uint32_t i;

	if (clean_only) {
		for (i = 0; i <= len; i += PRIME_CACHE_LINE_SIZE)
			dcbf(buf + i);
	} else {
		/* clean and invalidate */
		for (i = 0; i <= len; i += PRIME_CACHE_LINE_SIZE)
			dccivac(buf + i);
	}
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

	return 0;
}

static int test_1G_memory(void *va, uint64_t phys, size_t size)
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
	op_serv_args[0].physical_addr = phys;    // 36-bit address example
	op_serv_args[0].size  = size;
	err = prime_open_service(&op_serv_args[0], &serv_hdl);

	if (err) {
		printf("Failed to open prime service\n");
		return err;
	}

	if (hmac_test(serv_hdl, va, phys))
		return -1;

	printf("SHA2-256-HMAC test passed\n");

	if (aes_cbc_test(serv_hdl, va, phys))
		return -1;

	printf("AES-256-CBC test passed\n");

	if (aes_ecb_test(serv_hdl, va, phys))
		return -1;

	printf("AES-256-ECB test passed\n");

	if (aes_ctr_test(serv_hdl, va, phys))
		return -1;

	printf("AES-256-CTR (8192B) and (256B) test passed\n");

	if (aes_gcm_test(serv_hdl, va, phys))
		return -1;

	printf("AES-256-GCM(256B) test passed\n");

	prime_close_service(op_serv_args[0].service_hdl);

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_256MB_4_session(void *va, uint64_t phys, size_t size)
{
	prime_hdl_t serv_hdl;
	void *temp_va;
	uint64_t temp_phys;
	int32_t err, i;

	/* opening 4 session of 256 MB each, closing consecutively */
	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	memset(va, 0, SIZE_1GB);
	printf("\nExecuting %s\n", __func__);
	temp_va = va;
	temp_phys = phys;
	for (i = 0; i < 4; i++) {
		op_serv_args[i].size = SIZE_256MB; // 256 MB
#ifdef DEBUG
		printf("VA = %p\n", temp_va);
		printf("PA = 0x%012" PRIx64 "\n", temp_phys);
		printf("Aligned? %s\n", (temp_phys % SIZE_256MB == 0 ? "YES" : "NO"));
#endif
		op_serv_args[i].serv_type = SERVICE_TYPE_ALL;
		op_serv_args[i].physical_addr = temp_phys;    // 36-bit address example
		op_serv_args[i].size  = SIZE_256MB;
		err = prime_open_service(&op_serv_args[i], &serv_hdl);

		if (err) {
			printf("Failed to open %dth prime service\n", i);
			return err;
		}
		if (execute_crypto_test(serv_hdl, temp_va, temp_phys))
			return -1;

		temp_va += SIZE_256MB;
		temp_phys += SIZE_256MB;

		prime_close_service(op_serv_args[i].service_hdl);
	}

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_256MB_4_session_close_in_end(void *va, uint64_t phys, size_t size)
{
	prime_hdl_t serv_hdl;
	void *temp_va;
	uint64_t temp_phys;
	int32_t err, i;

	/* opening 4 session of 256 MB each, closing together in the end */
	printf("\nExecuting %s\n", __func__);
	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	memset(va, 0, SIZE_1GB);
	temp_va = va;
	temp_phys = phys;
	for (i = 0; i < 4; i++) {
#ifdef DEBUG
		printf("VA = %p\n", temp_va);
		printf("PA = 0x%012" PRIx64 "\n", temp_phys);
		printf("Aligned? %s\n", (temp_phys % SIZE_256MB == 0 ? "YES" : "NO"));
#endif
		op_serv_args[i].serv_type = SERVICE_TYPE_ALL;
		op_serv_args[i].physical_addr = temp_phys;    // 36-bit address example
		op_serv_args[i].size = SIZE_256MB; // 256 MB
		err = prime_open_service(&op_serv_args[i], &serv_hdl);

		if (err) {
			printf("%dth prime service open failed : FAILURE\n", i);
			return err;
		}
		if (execute_crypto_test(serv_hdl, temp_va, temp_phys))
			return -1;

		temp_va += SIZE_256MB;
		temp_phys += SIZE_256MB;
	}

	for (i = 0; i < 4; i++) {
		if (op_serv_args[i].service_hdl)
			prime_close_service(op_serv_args[i].service_hdl);
	}

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_in_range_addr(void *va, uint64_t phys, size_t size)
{
	prime_hdl_t serv_hdl;
	void *temp_va;
	uint64_t temp_phys;
	int32_t err, i;

	/* open a session with address in between the mapped window */
	printf("\nExecuting %s\n", __func__);
	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	memset(va, 0, SIZE_1GB);
	op_serv_args[0].serv_type = SERVICE_TYPE_ALL;
	op_serv_args[0].physical_addr = phys;    // 36-bit address example
	op_serv_args[0].size  = size;
	err = prime_open_service(&op_serv_args[0], &serv_hdl);

	if (err) {
		printf("Failed to open prime service\n");
		return err;
	}

	if (execute_crypto_test(serv_hdl, va, phys))
		return -1;

	temp_va = va + SIZE_256MB;
	temp_phys = phys + SIZE_256MB;
#ifdef DEBUG
	printf("VA = %p\n", temp_va);
	printf("PA = 0x%012" PRIx64 "\n", temp_phys);
	printf("Aligned? %s\n", (temp_phys % SIZE_256MB == 0 ? "YES" : "NO"));
#endif
	op_serv_args[1].serv_type = SERVICE_TYPE_ALL;
	op_serv_args[1].physical_addr = temp_phys;    // 36-bit address example
	op_serv_args[1].size = SIZE_256MB; // 256 MB
	err = prime_open_service(&op_serv_args[1], &serv_hdl);

	if (err) {
		printf("Failed to open intermediate prime service\n");
		return err;
	}

	if (execute_crypto_test(serv_hdl, temp_va, temp_phys))
		return -1;

#ifdef SE_NEG_TEST
	prime_close_service(op_serv_args[1].service_hdl); //This must not unmap ATU
#endif
	prime_close_service(op_serv_args[1].service_hdl); //it must pass
	prime_close_service(op_serv_args[0].service_hdl);

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_out_of_range_addr(void *va, uint64_t phys, size_t size)
{
	prime_hdl_t serv_hdl;
	void *temp_va;
	uint64_t temp_phys;
	int32_t err, i;

	/* open a session with address beyond the mapped window */
	printf("\nExecuting %s\n", __func__);
	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	memset(va, 0, SIZE_1GB);
	op_serv_args[0].serv_type = SERVICE_TYPE_ALL;
	op_serv_args[0].physical_addr = phys;    // 36-bit address example
	op_serv_args[0].size  = size;
	err = prime_open_service(&op_serv_args[0], &serv_hdl);
	if (err) {
		printf("Failed to open prime service\n");
		return err;
	}

	if (execute_crypto_test(serv_hdl, va, phys))
		return -1;

	temp_va = va + SIZE_1GB;
	temp_phys = phys + SIZE_1GB;
#ifdef DEBUG
	printf("VA = %p\n", temp_va);
	printf("PA = 0x%012" PRIx64 "\n", temp_phys);
	printf("Aligned? %s\n", (temp_phys % SIZE_256MB == 0 ? "YES" : "NO"));
#endif
	op_serv_args[1].serv_type = SERVICE_TYPE_ALL;
	op_serv_args[1].physical_addr = temp_phys;    // 36-bit address example
	op_serv_args[1].size = SIZE_256MB; // 256 MB
	err = prime_open_service(&op_serv_args[1], &serv_hdl);

	if (err)
		printf("Failure expected for unauthorized address : SUCCESS\n");

	prime_close_service(op_serv_args[0].service_hdl);

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_user_alloc_flow(void)
{
	prime_hdl_t serv_hdl;
	int32_t err, i;
	uint64_t phys;
	int use_1g = 1;
	size_t size = use_1g ? (1UL << 30) : (32UL << 20);
	int flag = use_1g ? MAP_HUGE_1GB : MAP_HUGE_32MB;
	uint64_t temp_phys;
	void *temp_va;
	void *va = alloc_huge(size, flag, &phys);

	if (!va)
		return 1;

	err = test_1G_memory(va, phys, size);
	if (err)
		return err;

	err = test_256MB_4_session(va, phys, size);
	if (err)
		return err;

	err = test_256MB_4_session_close_in_end(va, phys, size);
	if (err)
		return err;

	err = test_in_range_addr(va, phys, size);
	if (err)
		return err;

	err = test_out_of_range_addr(va, phys, size);
	if (err)
		return err;

	munmap(va, size);

	return err;
}

static int test_se_1G_memory(void)
{
	prime_hdl_t serv_hdl;
	int32_t err;
	uint64_t phys;

	printf("\nExecuting %s\n", __func__);

	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	op_serv_args[0].serv_type = SERVICE_TYPE_ALL;
	op_serv_args[0].size  = SIZE_1GB;
	err = prime_open_service(&op_serv_args[0], &serv_hdl);

	if (err) {
		printf("Failed to open prime service\n");
		return err;
	}

	dump_test_params(&op_serv_args[0]);

	if (hmac_test(serv_hdl, (void *)op_serv_args[0].virtual_addr,
		      op_serv_args[0].physical_addr))
		return -1;

	printf("SHA2-256-HMAC test passed\n");

	if (aes_cbc_test(serv_hdl, (void *)op_serv_args[0].virtual_addr,
			 op_serv_args[0].physical_addr))
		return -1;

	printf("AES-256-CBC test passed\n");

	if (aes_ecb_test(serv_hdl, (void *)op_serv_args[0].virtual_addr,
			 op_serv_args[0].physical_addr))
		return -1;

	printf("AES-256-ECB test passed\n");

	if (aes_ctr_test(serv_hdl, (void *)op_serv_args[0].virtual_addr,
			 op_serv_args[0].physical_addr))
		return -1;

	printf("AES-256-CTR (8192B) and (256B) test passed\n");

	if (aes_gcm_test(serv_hdl, (void *)op_serv_args[0].virtual_addr,
			 op_serv_args[0].physical_addr))
		return -1;

	printf("AES-256-GCM(256B) test passed\n");

	prime_close_service(op_serv_args[0].service_hdl);

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_se_256MB_6_reqs(void)
{
	prime_hdl_t serv_hdl;
	int32_t err, i;
	uint64_t phys;

	printf("\nExecuting %s\n", __func__);

	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	for (i = 0; i < 6; i++) {
		op_serv_args[i].serv_type = SERVICE_TYPE_ALL;
		op_serv_args[i].size  = SIZE_256MB;
		err = prime_open_service(&op_serv_args[i], &serv_hdl);

		if (err) {
			printf("Failed to open prime service\n");
			return err;
		}

		dump_test_params(&op_serv_args[i]);

		if (execute_crypto_test(serv_hdl, (void *)op_serv_args[i].virtual_addr,
					op_serv_args[i].physical_addr))
			return -1;

		prime_close_service(op_serv_args[i].service_hdl);
	}

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_se_256MB_4_reqs_again_256MB_2_reqs(void)
{
	prime_hdl_t serv_hdl;
	int32_t err, i;
	uint64_t phys;

	printf("\nExecuting %s\n", __func__);

	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	for (i = 0; i < 4; i++) {
		op_serv_args[i].serv_type = SERVICE_TYPE_ALL;
		op_serv_args[i].size  = SIZE_256MB;
		err = prime_open_service(&op_serv_args[i], &serv_hdl);

		if (err) {
			printf("Failed to open prime service\n");
			return err;
		}

		dump_test_params(&op_serv_args[i]);

		if (execute_crypto_test(serv_hdl, (void *)op_serv_args[i].virtual_addr,
					op_serv_args[i].physical_addr))
			return -1;
	}

	prime_close_service(op_serv_args[1].service_hdl);
	prime_close_service(op_serv_args[3].service_hdl);

	for (i = 1; i < 4; i += 2) {
		op_serv_args[i].serv_type = SERVICE_TYPE_ALL;
		op_serv_args[i].size  = SIZE_256MB;
		op_serv_args[i].virtual_addr = 0;
		op_serv_args[i].physical_addr = 0;
		err = prime_open_service(&op_serv_args[i], &serv_hdl);

		if (err) {
			printf("Failed to open prime service\n");
			return err;
		}

		dump_test_params(&op_serv_args[i]);

		if (execute_crypto_test(serv_hdl, (void *)op_serv_args[i].virtual_addr,
					op_serv_args[i].physical_addr))
			return -1;
	}

	for (i = 0; i < 4; i++)
		prime_close_service(op_serv_args[i].service_hdl);

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_se_256MB_4_reqs_512MB_neg(void)
{
	prime_hdl_t serv_hdl;
	int32_t err, i;
	uint64_t phys;

	printf("\nExecuting %s\n", __func__);

	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	for (i = 0; i < 4; i++) {
		op_serv_args[i].serv_type = SERVICE_TYPE_ALL;
		op_serv_args[i].size  = SIZE_256MB;
		err = prime_open_service(&op_serv_args[i], &serv_hdl);

		if (err) {
			printf("Failed to open prime service\n");
			return err;
		}

		dump_test_params(&op_serv_args[i]);

		if (execute_crypto_test(serv_hdl, (void *)op_serv_args[i].virtual_addr,
					op_serv_args[i].physical_addr))
			return -1;
	}

	prime_close_service(op_serv_args[1].service_hdl);
	prime_close_service(op_serv_args[3].service_hdl);

	op_serv_args[1].serv_type = SERVICE_TYPE_ALL;
	op_serv_args[1].size  = SIZE_512MB;
	op_serv_args[1].virtual_addr = 0;
	op_serv_args[1].physical_addr = 0;
	err = prime_open_service(&op_serv_args[1], &serv_hdl);

	if (err)
		printf("Failure expected as no contiguous memory of 512 MB: SUCCESS\n");

	for (i = 0; i < 4; i += 2)
		prime_close_service(op_serv_args[i].service_hdl);

	printf("%s completed successfully\n", __func__);
	return 0;
}

static int test_se_256MB_4_reqs_512MB_pos(void)
{
	prime_hdl_t serv_hdl;
	int32_t err, i;
	uint64_t phys;

	printf("\nExecuting %s\n", __func__);

	memset(&op_serv_args, 0, sizeof(open_service_args_t) * 6);
	for (i = 0; i < 4; i++) {
		op_serv_args[i].serv_type = SERVICE_TYPE_ALL;
		op_serv_args[i].size  = SIZE_256MB;
		err = prime_open_service(&op_serv_args[i], &serv_hdl);

		if (err) {
			printf("Failed to open prime service\n");
			return err;
		}

		dump_test_params(&op_serv_args[i]);

		if (execute_crypto_test(serv_hdl, (void *)op_serv_args[i].virtual_addr,
					op_serv_args[i].physical_addr))
			return -1;
	}

	prime_close_service(op_serv_args[1].service_hdl);
	prime_close_service(op_serv_args[2].service_hdl);

	op_serv_args[1].serv_type = SERVICE_TYPE_ALL;
	op_serv_args[1].size  = SIZE_512MB;
	op_serv_args[1].virtual_addr = 0;
	op_serv_args[1].physical_addr = 0;
	err = prime_open_service(&op_serv_args[1], &serv_hdl);

	if (err) {
		printf("Open service fail for 500MB request\n");
		return err;
	}

	dump_test_params(&op_serv_args[1]);

	if (execute_crypto_test(serv_hdl, (void *)op_serv_args[1].virtual_addr,
				op_serv_args[1].physical_addr))
		return -1;

	for (i = 0; i < 4; i++) {
		if (i == 2)
			continue;
		prime_close_service(op_serv_args[i].service_hdl);
	}

	printf("%s completed successfully\n", __func__);
	return 0;
}

#ifdef SE_NEG_TEST
static int test_se_oob(void)
{
	prime_hdl_t serv_hdl;
	int32_t err, i;
	uint64_t phys;

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
				op_serv_args[0].physical_addr))
		return -1;

	op_serv_args[0].virtual_addr += SIZE_256MB;

	if (execute_crypto_test(serv_hdl, (void *)op_serv_args[0].virtual_addr,
				op_serv_args[0].physical_addr))
		return -1;

	prime_close_service(op_serv_args[0].service_hdl);

	printf("%s completed successfully\n", __func__);
	return 0;
}
#endif

static int test_se_alloc_flow(void)
{
	int32_t err;

	err = test_se_1G_memory();
	if (err)
		return err;

	err = test_se_256MB_6_reqs();
	if (err)
		return err;

	err = test_se_256MB_4_reqs_again_256MB_2_reqs();
	if (err)
		return err;

	err = test_se_256MB_4_reqs_512MB_neg();
	if (err)
		return err;

	err = test_se_256MB_4_reqs_512MB_pos();
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
