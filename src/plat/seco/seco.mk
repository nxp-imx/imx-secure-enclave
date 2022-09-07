#
# Copyright 2021-2022 NXP
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

MINOR_VER := 0

HSM_TEST := $(PLAT)_hsm_test
SHE_TEST := $(PLAT)_she_test
V2X_TEST := $(PLAT)_v2x_test
SHE_LIB_NAME := lib$(PLAT)_she
HSM_LIB_NAME := lib$(PLAT)_hsm
NVM_LIB_NAME := lib$(PLAT)_nvm

DEFINES		+=	-DCONFIG_PLAT_SECO -DLIB_MINOR_VERSION=${MINOR_VER}\
			-DCONFIG_COMPRESSED_ECC_POINT

PLAT_OBJECTS	:=	$(PLAT_PATH)/seco_os_abs_linux.o \
			$(PLAT_PATH)/seco_utils.o \
			$(PLAT_PATH)/plat_err.o

OBJECTS	+= $(PLAT_OBJECTS)
