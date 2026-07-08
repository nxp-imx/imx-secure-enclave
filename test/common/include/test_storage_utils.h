// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef TEST_STORAGE_UTILS_H
#define TEST_STORAGE_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include "hsm_api.h"

#define NVM_DAEMON_TIMEOUT_SEC 10
#define NVM_POLL_INTERVAL_MS   200

/**
 * Execute systemctl command with proper error checking
 * Returns: 0 on success, -1 on failure
 */
int execute_systemctl_cmd(const char *action, const char *service_name);

/**
 * Check whether a systemd service is currently active.
 * Returns: 1 if running, 0 if not running, -1 on error
 */
int is_nvm_service_running(const char *service_name);

/**
 * Wait for NVM storage to reach desired state using HSM API
 * Returns: 0 on success, -1 on timeout or error
 */
int wait_for_nvm_state(hsm_hdl_t session_hdl, uint32_t mu_type,
		       bool should_be_open, uint32_t timeout_sec);

/**
 * Start NVM daemon and wait for storage to be ready
 * Returns: 0 on success, non-zero on failure
 */
int start_nvm_daemon_wait(const char *service_name, hsm_hdl_t session_hdl,
			  uint32_t mu_type, uint32_t timeout_sec);

/**
 * Stop NVM daemon and wait for storage to close
 * Returns: 0 on success, non-zero on failure
 */
int stop_nvm_daemon_wait(const char *service_name, hsm_hdl_t session_hdl,
			 uint32_t mu_type, uint32_t timeout_sec);

int start_daemon(const char *service_name);
int stop_daemon(const char *service_name);
#endif /* TEST_STORAGE_UTILS_H */
