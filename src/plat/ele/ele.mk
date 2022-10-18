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
SHE_TEST :=
V2X_TEST :=
SHE_LIB_NAME :=
HSM_LIB_NAME := lib$(PLAT)_hsm
NVM_LIB_NAME := lib$(PLAT)_nvm

DEFINES		+=	-DCONFIG_PLAT_ELE -DPLAT_ELE_FEAT_NOT_SUPPORTED=0 \
			-DLIB_MINOR_VERSION=${MINOR_VER} -DPSA_COMPLIANT \
			-DSECONDARY_API_SUPPORTED

PLAT_OBJECTS	:=	$(PLAT_PATH)/ele_os_abs_linux.o \
			$(PLAT_PATH)/ele_utils.o \
			$(PLAT_PATH)/plat_err.o

OBJECTS	+= $(PLAT_OBJECTS)
