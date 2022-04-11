# Copyright 2022 NXP
#
# NXP Confidential.
# This software is owned or controlled by NXP and may only be used strictly
# in accordance with the applicable license terms.  By expressly accepting
# such terms or by downloading, installing, activating and/or otherwise using
# the software, you are agreeing that you have read, and that you agree to
# comply with and are bound by, such license terms.  If you do not agree to be
# bound by the applicable license terms, then you may not retain, install,
# activate or otherwise use the software.
#

include $(PLAT_PATH)/sab_msg.def

SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_process_msg.o \
		$(PLAT_COMMON_PATH)/sab_msg/sab_init_proc_msg.o \

ifneq (${MT_SAB_DEBUG_DUMP},0x0)
DEFINES		+=	-DMT_SAB_DEBUG_DUMP=${MT_SAB_DEBUG_DUMP}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_debug_dump.o
endif

ifneq (${MT_SAB_MANAGE_KEY},0x0)
DEFINES		+=	-DMT_SAB_MANAGE_KEY=${MT_SAB_MANAGE_KEY}
SAB_MSG_SRC	+= \
		$(PLAT_COMMON_PATH)/sab_msg/sab_managekey.o
endif

OBJECTS		+= $(SAB_MSG_SRC)

INCLUDE_PATHS	+= \
       		-I${PLAT_COMMON_PATH}/sab_msg/include
