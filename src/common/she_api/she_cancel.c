// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "sab_process_msg.h"

void she_cmd_cancel(void)
{
	send_cancel_signal_to_engine();
}
