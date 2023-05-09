// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <ele_perf.h>

/**
 * diff_microsec - Returns the time difference between start and end time
 *
 * @start_time: pointer to the structure for start time.
 *
 * @end_time: pointer to the structure for end time.
 *
 * Convenience function that takes pointer to the structures for the start
 * and end time for any operation and returns the time difference in
 * microseconds.
 */
float diff_microsec(struct timespec *start_time, struct timespec *end_time)
{
	if (!start_time || !end_time) {
		se_err("Invalid start_time and end_time pointers");
		return 0;
	}

	float diff = (float)(end_time->tv_sec - start_time->tv_sec) *
			 SEC_TO_MICROSEC + ((float)end_time->tv_nsec - start_time->tv_nsec) /
			 SEC_TO_MILLISEC;
	return diff;
}

/**
 * update_stats - Update the statistics pointer after new operation
 *
 * @perf_data: pointer to the statistics structure storing performance data.
 *
 * @time_per_op_start: pointer to the structure for start time of operation.
 *
 * @time_per_op_end: pointer to the structure for end time of operation.
 *
 * Convenience function for updating the statistics structure after each
 * new operation.
 */
void update_stats(statistics *perf_data, struct timespec *time_per_op_start,
		  struct timespec *time_per_op_end)
{
	if (!perf_data || !time_per_op_start || !time_per_op_end) {
		se_err("Accessing invalid pointers\n");
		return;
	}

	float diff = diff_microsec(time_per_op_start, time_per_op_end);

	if (diff == 0)
		return;
	perf_data->total_time += diff;
	float delta = diff - perf_data->mean_time;

	perf_data->no_of_ops++;

	float delta_per_op = delta / perf_data->no_of_ops;

	perf_data->mean_time += delta_per_op;
}

/**
 * kb_per_sec - Print the performance in kilobytes per second
 *
 * @size: variable to store key size used for the operation.
 *
 * @usec: variable to store the total time in microseconds.
 *
 * Convenience function for printing the performance for the operation in
 * kilobytes per second.
 */
float kb_per_sec(size_t size, float usec)
{
	if (usec == 0)
		return 0;

	return (SEC_TO_MICROSEC / usec) * ((float)size / BYTE_TO_KILOBYTE);
}

/**
 * print_perf_data - Print the performance data
 *
 * @perf_data: pointer to the statistics structure storing performance data.
 *
 * @size: variable to store key size used for the operation.
 *
 * @algo: storing the algorithm used.
 *
 * @ciphertext_size: variable to store the data block size.
 *
 * Convenience function for printing the performance for the operation in
 * terms of mean time, number of operations, total time etc.
 */
void print_perf_data(statistics *perf_data, uint32_t size, const char *algo,
		     uint32_t ciphertext_size)
{
	if (!perf_data || !algo) {
		se_err("Invalid perf_data or algo pointer\n");
		return;
	}

	printf("%d ops %s-%d's in %.4fs(%.0fus/ops)\n", perf_data->no_of_ops, algo, size,
	       perf_data->total_time / SEC_TO_MICROSEC, perf_data->mean_time);
}

/**
 * cipher_algo_to_string - Return the cipher algorithm pointed by the value
 *
 * @val: variable storing value pointing to the algorithm used
 *
 * Convenience function that takes a value as an argument and maps it
 * to the cipher algorithm used and returns the algorithm.
 */
const char *cipher_algo_to_string(uint32_t val)
{
	switch (val) {
	case ALGO_CIPHER_ECB_NO_PAD:
		return "AES-ECB";

	case ALGO_CIPHER_CBC_NO_PAD:
		return "AES-CBC";

	case ALGO_CIPHER_CTR:
		return "AES-CTR";

	case ALGO_CIPHER_CFB:
		return "AES-CFB";

	case ALGO_CIPHER_OFB:
		return "AES-OFB";
	default:
		return NULL;
	}
	return NULL;
}

/**
 * scheme_algo_to_string - Return the signing algorithm pointed by the value
 *
 * @val: variable storing Hexvalue pointing to the algorithm used
 *
 * Convenience function that takes a Hexval as an argument and maps it
 * to the signing algorithm used and returns the algorithm.
 */
const char *scheme_algo_to_string(uint32_t val)
{
	if (val >= ALGO_ECDSA_SHA224 && val <= ALGO_ECDSA_SHA512)
		return "ECDSA_SHA";
	return NULL;
}

/**
 * mac_algo_to_string - Return the mac algorithm pointed by the value
 *
 * @val: variable storing value pointing to the algorithm used
 *
 * Convenience function that takes a value as an argument and maps it
 * to the mac algorithm used and returns the algorithm.
 */
const char *mac_algo_to_string(uint32_t val)
{
	switch (val) {
	case ALGO_HMAC_SHA256:
	case ALGO_HMAC_SHA384:
		return "HMAC_SHA";
	case ALGO_CMAC:
		return "CMAC";
	default:
		return NULL;
	}
}
