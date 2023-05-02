# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2021-2023 NXP
#

MINOR_VER := 0

HSM_TEST := $(PLAT)_hsm_test
HSM_PERF_TEST := $(PLAT)_hsm_perf_test
TEST_PERF_CFLAGS := -DELE_PERF
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
