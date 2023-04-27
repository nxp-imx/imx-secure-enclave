# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2021-2022 NXP
#

MINOR_VER := 0

HSM_TEST := $(PLAT)_hsm_test
SHE_TEST := $(PLAT)_she_test
V2X_TEST := $(PLAT)_v2x_test
SHE_LIB_NAME := lib$(PLAT)_she
HSM_LIB_NAME := lib$(PLAT)_hsm
NVM_LIB_NAME := lib$(PLAT)_nvm
HSM_LIB_OBJECTS += $(PLAT_COMMON_PATH)/hsm_lib_non_psa.o

DEFINES		+=	-DCONFIG_PLAT_SECO -DLIB_MINOR_VERSION=${MINOR_VER}\
			-DCONFIG_COMPRESSED_ECC_POINT

PLAT_OBJECTS	:=	$(PLAT_PATH)/seco_os_abs_linux.o \
			$(PLAT_PATH)/seco_utils.o \
			$(PLAT_PATH)/plat_err.o

OBJECTS	+= $(PLAT_OBJECTS) \
		${HSM_LIB_OBJECTS}
