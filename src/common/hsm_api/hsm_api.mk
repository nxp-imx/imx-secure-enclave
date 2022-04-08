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

HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_handle.o \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_utils.o \

ifneq (${MT_SAB_MANAGE_KEY},0x0)
DEFINES		+=	-DHSM_MANAGE_KEY
HSM_API_SRC	+= \
		$(PLAT_COMMON_PATH)/hsm_api/hsm_managekey.o
endif

OBJECTS		+= $(HSM_API_SRC)

INCLUDE_PATHS += \
       		-I${PLAT_COMMON_PATH}/hsm_api/include
