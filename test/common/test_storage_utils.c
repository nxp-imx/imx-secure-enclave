// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <stdbool.h>

#include "hsm_api.h"
#include "nvm.h"
#include "plat_utils.h"
#include "test_storage_utils.h"

#define NVM_STOP_GRACE_PERIOD_MS 500
#define NVM_STOP_TIMEOUT_SEC 5

/*
 * The HSM storage-status API (hsm_get_storage_status and the
 * HSM_STORAGE_STATUS_* values) is only available on PSA compliant platforms
 * that support the storage-status message. When it is not available the NVM
 * state is inferred from the systemd service state instead.
 */
#if defined(PSA_COMPLIANT) && MT_SAB_STORAGE_STATUS
#define HSM_STORAGE_STATUS_SUPPORTED 1
#else
#define HSM_STORAGE_STATUS_SUPPORTED 0
#endif

/**
 * Check if systemd service is actually running
 * Returns: 1 if running, 0 if not running, -1 on error
 */
static int is_service_running(const char *service_name)
{
	char cmd[256];
	int status;

	snprintf(cmd, sizeof(cmd), "systemctl is-active --quiet %s", service_name);
	status = system(cmd);

	if (status == -1) {
		fprintf(stderr, "Error: Failed to check service status\n");
		return -1;
	}

	return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 1 : 0;
}

/**
 * Public wrapper exposing the service-running check so callers can decide
 * whether they started a daemon (and therefore should stop it) versus
 * finding it already running (and leaving it as-is).
 */
int is_nvm_service_running(const char *service_name)
{
	if (!service_name) {
		fprintf(stderr, "Error: NULL service name\n");
		return -1;
	}

	return is_service_running(service_name);
}

/**
 * Execute systemctl command with proper error checking
 */
int execute_systemctl_cmd(const char *action, const char *service_name)
{
	char cmd[256];
	int status;

	if (!action || !service_name) {
		fprintf(stderr, "Error: NULL action or service name\n");
		return -1;
	}

	snprintf(cmd, sizeof(cmd), "systemctl %s %s", action, service_name);

	status = system(cmd);
	if (status == -1) {
		fprintf(stderr, "Error: system() call failed for '%s'\n", cmd);
		return -1;
	}

	if (!WIFEXITED(status)) {
		fprintf(stderr, "Error: Command did not exit normally: '%s'\n", cmd);
		return -1;
	}

	if (WEXITSTATUS(status) != 0) {
		fprintf(stderr, "Error: Command failed (exit code: %d): '%s'\n",
			WEXITSTATUS(status), cmd);
		return -1;
	}

	return 0;
}

#if !HSM_STORAGE_STATUS_SUPPORTED
/**
 * Wait for a systemd service to reach the desired active state.
 * Returns: 0 on success, -1 on timeout or error
 */
static int wait_for_service_state(const char *service_name, int want_running,
				  uint32_t timeout_sec)
{
	struct timespec start, current;
	double elapsed;
	int running;

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
		fprintf(stderr, "Error: Failed to get start time\n");
		return -1;
	}

	while (1) {
		running = is_service_running(service_name);

		/*
		 * is_service_running() returns -1 when the underlying
		 * system() call fails. Bail out immediately in that case
		 * instead of spinning until the timeout and masking the
		 * real error.
		 */
		if (running < 0) {
			fprintf(stderr, "Error: Failed to query state of %s\n",
				service_name);
			return -1;
		}

		if (running == want_running)
			return 0;

		if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) {
			fprintf(stderr, "Error: Failed to get current time\n");
			return -1;
		}

		elapsed = (current.tv_sec - start.tv_sec) +
			  (current.tv_nsec - start.tv_nsec) / 1e9;

		if (elapsed >= timeout_sec) {
			fprintf(stderr, "Error: Timeout waiting for %s to become %s\n",
				service_name, want_running ? "active" : "inactive");
			return -1;
		}

		usleep(NVM_POLL_INTERVAL_MS * 1000);
	}

	return 0;
}
#endif

/**
 * Wait for NVM storage to reach desired state using HSM API
 */
int wait_for_nvm_state(hsm_hdl_t session_hdl, uint32_t mu_type,
		       bool should_be_open, uint32_t timeout_sec)
{
#if HSM_STORAGE_STATUS_SUPPORTED
	struct timespec start, current;
	double elapsed;
	/*
	 * Initialize to a defined value so a failed status query does not
	 * leave storage_status holding an indeterminate result that could
	 * be misread on the first iteration.
	 */
	hsm_storage_status_t storage_status = HSM_STORAGE_STATUS_NOT_OPENED;
	hsm_err_t err;
	uint32_t poll_ms = NVM_POLL_INTERVAL_MS;

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
		fprintf(stderr, "Error: Failed to get start time\n");
		return -1;
	}

	while (1) {
		err = hsm_get_storage_status(session_hdl, mu_type, &storage_status);

		if (should_be_open) {
			if (err == HSM_NO_ERROR &&
			    storage_status == HSM_STORAGE_STATUS_OPENED) {
				printf("NVM storage is now OPENED\n");
				return 0;
			}
		} else {
			/*
			 * When waiting for the storage to close, a failed
			 * status query (err != HSM_NO_ERROR) is treated as
			 * closed, since the daemon backing the storage is
			 * expected to be gone. storage_status is only trusted
			 * when the query actually succeeded, so a failed call
			 * cannot be misread from a stale/uninitialized value.
			 */
			if (err != HSM_NO_ERROR ||
			    storage_status == HSM_STORAGE_STATUS_NOT_OPENED ||
			    storage_status == HSM_STORAGE_STATUS_FETCH_FAILED) {
				printf("NVM storage is now CLOSED\n");
				return 0;
			}
		}

		if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) {
			fprintf(stderr, "Error: Failed to get current time\n");
			return -1;
		}

		elapsed = (current.tv_sec - start.tv_sec) +
			  (current.tv_nsec - start.tv_nsec) / 1e9;

		if (elapsed >= timeout_sec) {
			fprintf(stderr, "Error: Timeout waiting for storage to be %s\n",
				should_be_open ? "OPENED" : "CLOSED");
			fprintf(stderr, "Last status: %d, HSM error: 0x%x\n",
				storage_status, err);
			return -1;
		}

		usleep(poll_ms * 1000);
	}

	return -1;
#else
	/*
	 * Storage-status API is not available on this platform. The service
	 * state is polled by the start/stop helpers instead, so there is
	 * nothing to wait for here.
	 */
	(void)session_hdl;
	(void)mu_type;
	(void)should_be_open;
	(void)timeout_sec;
	return 0;
#endif
}

/**
 * Start NVM daemon and wait for storage to be ready
 */
int start_nvm_daemon_wait(const char *service_name, hsm_hdl_t session_hdl,
			  uint32_t mu_type, uint32_t timeout_sec)
{
	int running;

	if (!service_name) {
		fprintf(stderr, "Error: NULL service name\n");
		return -1;
	}

	running = is_service_running(service_name);
	if (running == -1) {
		fprintf(stderr, "Error: Failed to check service status\n");
		return -1;
	}

#if HSM_STORAGE_STATUS_SUPPORTED
	{
		hsm_storage_status_t storage_status;
		hsm_err_t err;

		if (running == 1) {
			printf("Service %s is already running, checking storage status\n",
			       service_name);

			err = hsm_get_storage_status(session_hdl, mu_type,
						     &storage_status);
			if (err == HSM_NO_ERROR &&
			    storage_status == HSM_STORAGE_STATUS_OPENED) {
				printf("NVM storage already opened for %s\n",
				       service_name);
				return 0;
			}

			printf("Warning: storage not opened, restarting service\n");
			if (execute_systemctl_cmd("restart", service_name) != 0) {
				fprintf(stderr, "Error: Failed to restart %s\n",
					service_name);
				return -1;
			}
		} else {
			if (execute_systemctl_cmd("start", service_name) != 0) {
				fprintf(stderr, "Error: Failed to start %s\n",
					service_name);
				return -1;
			}
			printf("Started %s, waiting for storage to be ready\n",
			       service_name);
		}

		return wait_for_nvm_state(session_hdl, mu_type, true, timeout_sec);
	}
#else
	(void)session_hdl;
	(void)mu_type;

	if (running == 1) {
		printf("Service %s is already running\n", service_name);
		return 0;
	}

	if (execute_systemctl_cmd("start", service_name) != 0) {
		fprintf(stderr, "Error: Failed to start %s\n", service_name);
		return -1;
	}

	printf("Started %s, waiting for service to be active\n", service_name);
	return wait_for_service_state(service_name, 1, timeout_sec);
#endif
}

/**
 * Force kill service if normal stop fails
 */
static int force_kill_service(const char *service_name)
{
	printf("Warning: Attempting force kill of %s\n", service_name);

	if (execute_systemctl_cmd("kill", service_name) != 0) {
		fprintf(stderr, "Error: Failed to kill %s\n", service_name);
		return -1;
	}

	usleep(NVM_STOP_GRACE_PERIOD_MS * 1000);

	if (is_service_running(service_name) == 1) {
		fprintf(stderr, "Error: Service still running after kill attempt\n");
		return -1;
	}

	printf("Service forcefully stopped\n");
	return 0;
}

/**
 * Stop NVM daemon and wait for storage to close
 */
int stop_nvm_daemon_wait(const char *service_name, hsm_hdl_t session_hdl,
			 uint32_t mu_type, uint32_t timeout_sec)
{
	struct timespec start, current;
	double elapsed;
	int running;
	int force_killed = 0;

#if !HSM_STORAGE_STATUS_SUPPORTED
	/*
	 * session_hdl and mu_type are only consumed by the PSA storage-status
	 * confirmation below. On non-PSA builds that confirmation is compiled
	 * out, so silence the unused-parameter warnings here.
	 */
	(void)session_hdl;
	(void)mu_type;
#endif

	if (!service_name) {
		fprintf(stderr, "Error: NULL service name\n");
		return -1;
	}

	/*
	 * The force-kill fallback below fires once elapsed reaches
	 * NVM_STOP_TIMEOUT_SEC, while the final give-up check uses the
	 * caller-supplied timeout_sec. If timeout_sec were smaller than
	 * NVM_STOP_TIMEOUT_SEC the final timeout would trip first and the
	 * force-kill branch would never run, silently disabling the fallback.
	 * Clamp the effective timeout to at least NVM_STOP_TIMEOUT_SEC so the
	 * force-kill attempt is always reached before giving up.
	 */
	if (timeout_sec < NVM_STOP_TIMEOUT_SEC) {
		fprintf(stderr,
			"Warning: timeout_sec (%u) below force-kill threshold (%d), clamping to %d\n",
			timeout_sec, NVM_STOP_TIMEOUT_SEC, NVM_STOP_TIMEOUT_SEC);
		timeout_sec = NVM_STOP_TIMEOUT_SEC;
	}

	running = is_service_running(service_name);
	if (running == -1) {
		fprintf(stderr, "Error: Failed to check service status\n");
		return -1;
	}

	if (running == 0) {
		printf("Service %s is already stopped\n", service_name);
		return 0;
	}

	printf("Stopping %s\n", service_name);
	if (execute_systemctl_cmd("stop", service_name) != 0) {
		fprintf(stderr, "Error: systemctl stop command failed for %s\n",
			service_name);
		return -1;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
		fprintf(stderr, "Error: Failed to get start time\n");
		return -1;
	}

	while (1) {
		running = is_service_running(service_name);
		if (running == -1) {
			fprintf(stderr,
				"Error: Failed to check service status during stop\n");
			return -1;
		}

		if (running == 0) {
			printf("Service %s confirmed stopped\n", service_name);
			usleep(NVM_STOP_GRACE_PERIOD_MS * 1000);
			return 0;
		}

		if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) {
			fprintf(stderr, "Error: Failed to get current time\n");
			return -1;
		}

		elapsed = (current.tv_sec - start.tv_sec) +
			  (current.tv_nsec - start.tv_nsec) / 1e9;

		if (elapsed >= NVM_STOP_TIMEOUT_SEC && !force_killed) {
			fprintf(stderr,
				"Warning: Service did not stop within %d seconds\n",
				NVM_STOP_TIMEOUT_SEC);

			if (force_kill_service(service_name) != 0)
				return -1;

			force_killed = 1;
			if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
				fprintf(stderr, "Error: Failed to reset timer\n");
				return -1;
			}
			continue;
		}

		if (elapsed >= timeout_sec) {
			fprintf(stderr,
				"Error: Service did not stop within %d seconds (final timeout)\n",
				timeout_sec);
			fprintf(stderr,
				"Service may be hung - manual intervention required\n");
			return -1;
		}

		usleep(NVM_POLL_INTERVAL_MS * 1000);
	}

	return -1;
}

/*
 * This test has no HSM session handle available, so the shared helpers are
 * driven with a null handle. On non-PSA builds (where this test runs) the
 * helpers fall back to polling the systemd service state, which is exactly
 * what this test needs.
 */
#define NVM_MGR_SESSION_HDL 0
#define NVM_MGR_MU_TYPE     0

/*
 * Ownership is tracked per service, not with a single global. A single
 * process (for example the V2X HSM test) can drive more than one service
 * (nvm_daemon and nvm_daemon_v2x_hsm.service). A shared flag would let the
 * second start_daemon() overwrite the first service's ownership, so a later
 * stop_daemon() could act on the wrong service. Keying the flag by service
 * name keeps each service's "did this process start it" state independent.
 */
#define NVM_MAX_TRACKED_SERVICES 8
#define NVM_SERVICE_NAME_LEN     128

struct nvm_service_state {
	char name[NVM_SERVICE_NAME_LEN];
	uint32_t status;
};

static struct nvm_service_state nvm_services[NVM_MAX_TRACKED_SERVICES];

/*
 * Return the tracking slot for service_name, allocating a free slot on first
 * use. Returns NULL if service_name is NULL or the table is full.
 */
static struct nvm_service_state *nvm_service_slot(const char *service_name)
{
	int free_idx = -1;
	int i;

	if (!service_name) {
		fprintf(stderr, "Error: NULL service name\n");
		return NULL;
	}

	for (i = 0; i < NVM_MAX_TRACKED_SERVICES; i++) {
		if (nvm_services[i].name[0] == '\0') {
			if (free_idx == -1)
				free_idx = i;
			continue;
		}

		if (strcmp(nvm_services[i].name, service_name) == 0)
			return &nvm_services[i];
	}

	if (free_idx == -1) {
		fprintf(stderr, "Error: No free slot to track service %s\n",
			service_name);
		return NULL;
	}

	snprintf(nvm_services[free_idx].name,
		 sizeof(nvm_services[free_idx].name), "%s", service_name);
	nvm_services[free_idx].status = 0;
	return &nvm_services[free_idx];
}

/*
 * Start a daemon and wait until it becomes active.
 * If the daemon was already running before the test, remember it (per service)
 * so the matching stop leaves it as-found. Returns 0 on success, non-zero on
 * failure.
 */
int start_daemon(const char *service_name)
{
	struct nvm_service_state *svc;

	svc = nvm_service_slot(service_name);
	if (!svc)
		return -1;

	if (is_nvm_service_running(service_name) == 1) {
		svc->status = NVM_STATUS_RUNNING;
		return 0;
	}

	if (start_nvm_daemon_wait(service_name, NVM_MGR_SESSION_HDL,
				  NVM_MGR_MU_TYPE, NVM_DAEMON_TIMEOUT_SEC) != 0) {
		printf("Error: Failed to start %s\n", service_name);
		return -1;
	}

	svc->status = NVM_STATUS_STOPPED;
	return 0;
}

/*
 * Stop a daemon and wait until it becomes inactive.
 * A daemon that was already running when this process first saw it is left
 * untouched. The decision is made per service. Returns 0 on success, non-zero
 * on failure.
 */
int stop_daemon(const char *service_name)
{
	struct nvm_service_state *svc;

	svc = nvm_service_slot(service_name);
	if (!svc)
		return -1;

	/*
	 * Leave the service as-found: if it was already running when this
	 * process first saw it (NVM_STATUS_RUNNING), this process does not
	 * own it and must not stop it. Only a service this process started
	 * (recorded as NVM_STATUS_STOPPED, i.e. it was stopped beforehand)
	 * is stopped here to restore the original state.
	 */
	if (svc->status == NVM_STATUS_RUNNING) {
		printf("%s was already running, not stopping\n", service_name);
		return 0;
	}

	if (stop_nvm_daemon_wait(service_name, NVM_MGR_SESSION_HDL,
				 NVM_MGR_MU_TYPE, NVM_DAEMON_TIMEOUT_SEC) != 0) {
		printf("Error: Failed to stop %s\n", service_name);
		return -1;
	}

	return 0;
}
