# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2021-2024 NXP
#

CFLAGS := -O1 -Werror -Wformat -fPIC
LDFLAGS =
DESTDIR ?= export
BINDIR ?= /usr/bin
libdir ?= /usr/lib
LIBDIR = $(libdir)
INCLUDEDIR ?= /usr/include
SYSTEMD_DIR ?= /etc/systemd/system
ETC_DIR ?= /etc
DATA_DIR ?= /usr/share
TEST_VECTOR_DEFAULT_DIR ?= $(DATA_DIR)/se/test_vectors
TARGET_README_DIR ?= $(DATA_DIR)/se
PLAT ?= seco
MAJOR_VER := 1
DEFINES += -DLIB_MAJOR_VERSION=${MAJOR_VER}
INCLUDE_HEADERS_CP =
NVMD_CONFIG_SCRIPT_CP =
STAGE_DIR := stage_dir

NVMD_CONF_FILE = nvmd.conf
NVM_DAEMON = nvm_daemon
SYSTEMD_NVM_SERVICE = $(NVM_DAEMON).service

EXPORT_NVM_DAEMON =
EXPORT_NVMD_CONF_FILE =
EXPORT_SYSTEMD_NVM_SERVICE =
EXPORT_V2X_NVM_DAEMON =
EXPORT_V2X_NVMD_CONF_FILE =
EXPORT_V2X_SYSTEMD_NVM_SERVICE =

SE_SCRIPTS_PATH := ./scripts/
OPENSSL_PATH ?= ../openssl/
SE_VER_FILE := ./include/hsm/internal/se_version.h

ifdef COVERAGE
GCOV_FLAGS :=-fprofile-arcs -ftest-coverage
endif

PLAT_PATH := src/plat/$(PLAT)
PLAT_COMMON_PATH := src/common

INCLUDE_PATHS := -I${PLAT_PATH}/include -I${PLAT_COMMON_PATH}/include -Iinclude -Iinclude/hsm -Iinclude/she -Iinclude/common

NVM_OBJECTS := \
	$(PLAT_COMMON_PATH)/nvm/nvm_manager.o \
	$(PLAT_PATH)/nvm_os_abs_linux.o

OBJECTS	:= $(NVM_OBJECTS)\
	$(PLAT_COMMON_PATH)/sab_messaging.o \
	$(PLAT_COMMON_PATH)/sab_common_err.o \
	$(PLAT_COMMON_PATH)/she_lib.o \
	$(PLAT_COMMON_PATH)/hsm_lib.o

NVM_LIB :=
NVM_LIB_MAJOR :=
HSM_LIB :=
HSM_LIB_MAJOR :=
SHE_LIB :=
SHE_LIB_MAJOR :=
SO_EXT =

include $(PLAT_COMMON_PATH)/sab_msg/sab_msg.mk
include $(PLAT_COMMON_PATH)/hsm_api/hsm_api.mk
include $(PLAT_COMMON_PATH)/she_api/she_api.mk
include $(PLAT_PATH)/$(PLAT).mk

TEST_COMMON_TV_PATH := test/common/test_vectors/$(PSA)

LIB_NAMES := $(HSM_LIB_NAME) $(NVM_LIB_NAME) $(SHE_LIB_NAME)

all_tests:= $(SHE_TEST) $(HSM_TEST) $(HSM_PERF_TEST) $(V2X_HSM_TEST) $(V2X_SHE_TEST)
all_libs:= $(SHE_LIB) $(NVM_LIB) $(HSM_LIB)


# Make targets, must need NVM-Daemon to run successfully.
tests: install_version $(all_tests) $(NVM_DAEMON) clean_ver_hfile
libs: install_version $(all_libs) $(NVM_DAEMON) clean_ver_hfile
all: install_version $(all_libs) $(all_tests) $(NVM_DAEMON) clean_ver_hfile

.PHONY: all clean

%.o: %.c
	@echo "  HOSTCC  $<"
	${CC} -c ${CFLAGS} ${GCOV_FLAGS} ${INCLUDE_PATHS} $< -o $@

# SHE lib
$(SHE_LIB): $(SHE_LIB_OBJECTS)\
	$(PLAT_COMMON_PATH)/she_lib.o \
	$(PLAT_PATH)/plat_err.o \
	$(PLAT_PATH)/$(PLAT)_utils.o \
	$(SHE_SAB_MSG_SRC) \
	$(PLAT_COMMON_PATH)/sab_msg/sab_session.o\
	$(SHE_API_SRC) \
	$(PLAT_COMMON_PATH)/sab_messaging.o \
	$(PLAT_COMMON_PATH)/sab_common_err.o \
	$(PLAT_PATH)/$(PLAT)_os_abs_linux.o
	$(CC) -shared -Wl,-soname,$(SHE_LIB_MAJOR) -fPIC -o $@ $^

# HSM lib
$(HSM_LIB): $(HSM_LIB_OBJECTS) \
	$(PLAT_COMMON_PATH)/hsm_lib.o \
	$(PLAT_PATH)/plat_err.o \
	$(PLAT_PATH)/$(PLAT)_utils.o \
	$(SAB_MSG_SRC) \
	$(PLAT_COMMON_PATH)/sab_msg/sab_session.o\
	$(HSM_API_SRC) \
	$(PLAT_COMMON_PATH)/sab_messaging.o \
	$(PLAT_COMMON_PATH)/sab_common_err.o \
	$(PLAT_PATH)/$(PLAT)_os_abs_linux.o
	$(CC) -shared -Wl,-soname,$(HSM_LIB_MAJOR) -fPIC -o $@ $^

# NVM manager lib
$(NVM_LIB): $(PLAT_COMMON_PATH)/nvm/nvm_manager.o\
	$(PLAT_COMMON_PATH)/sab_msg/sab_session.o\
	$(PLAT_COMMON_PATH)/sab_common_err.o\
	$(PLAT_COMMON_PATH)/sab_messaging.o \
	$(SAB_RCVMSG_SRC) \
	$(PLAT_PATH)/nvm_os_abs_linux.o\
	$(PLAT_PATH)/plat_err.o \
	$(PLAT_PATH)/$(PLAT)_os_abs_linux.o\
	$(PLAT_PATH)/$(PLAT)_utils.o
	$(CC) -shared -Wl,-soname,$(NVM_LIB_MAJOR) -fPIC -o $@ $^

#SHE test components
ifdef DEBUG
DEFINES=-DDEBUG
DEFINES=-DELE_DEBUG
endif

CFLAGS += ${DEFINES}
COMMON_TEST_OBJ=$(wildcard test/common/*.c)
HSM_TEST_PERF_OBJ := test/common/ele_perf.c \
			test/common/test_file_reader.c \
			test/common/test_utils.c \
			test/common/test_utils_tv.c \
			test/common/test_genkey_tv.c \
			test/common/test_cipher_tv.c \
			test/common/test_mac_tv.c \
			test/common/test_sign_verify_tv.c
COMMON_TEST_INC=-Itest/common/include/

HSM_TEST_OBJ= test/hsm/hsm_test.c $(COMMON_TEST_OBJ)
HSM_PERF_TEST_OBJ= test/hsm/hsm_perf_test.c $(HSM_TEST_PERF_OBJ)
TEST_CFLAGS = -Wno-deprecated-declarations $(CFLAGS)
TEST_LDFLAGS = -L $(OPENSSL_PATH) -lcrypto $(LDFLAGS) -lcrypto -lpthread
TEST_INCLUDE_PATHS = ${INCLUDE_PATHS} -I$(OPENSSL_PATH)/include
$(HSM_TEST): $(HSM_TEST_OBJ) $(HSM_LIB)
	$(CC) $^  -o $@ ${TEST_INCLUDE_PATHS} ${COMMON_TEST_INC} $(TEST_CFLAGS) $(TEST_LDFLAGS) $(GCOV_FLAGS)
$(HSM_PERF_TEST): $(HSM_PERF_TEST_OBJ) $(HSM_LIB)
	$(CC) $^  -o $@ ${TEST_INCLUDE_PATHS} ${COMMON_TEST_INC} $(TEST_CFLAGS) $(TEST_PERF_CFLAGS) $(TEST_LDFLAGS) $(GCOV_FLAGS)

SHE_COMMON_TEST_OBJ=$(wildcard test/she/*.c)
SHE_TEST_OBJ= test/she/seco/she_test.c $(SHE_COMMON_TEST_OBJ)
#SHE test app
$(SHE_TEST): $(SHE_TEST_OBJ) $(SHE_LIB)
	$(CC) $^  -o $@ ${TEST_INCLUDE_PATHS} ${COMMON_TEST_INC} $(TEST_CFLAGS) $(GCOV_FLAGS)

V2X_SHE_TEST_OBJ= test/she/v2x/v2x_she_test.c $(SHE_COMMON_TEST_OBJ)
#V2X-SHE test app
$(V2X_SHE_TEST): $(V2X_SHE_TEST_OBJ) $(SHE_LIB)
	$(CC) $^  -o $@ ${TEST_INCLUDE_PATHS} ${COMMON_TEST_INC} $(TEST_CFLAGS) $(GCOV_FLAGS)

V2X_HSM_TEST_OBJ=$(wildcard test/v2x/*.c)
$(V2X_HSM_TEST): $(V2X_HSM_TEST_OBJ) $(HSM_LIB)
	$(CC) $^  -o $@ ${INCLUDE_PATHS} $(CFLAGS) $(LDFLAGS) -lpthread $(GCOV_FLAGS)

# NVM Daemon
NVM_D_OBJ=$(wildcard src/common/nvm/*.c)
$(NVM_DAEMON): $(NVM_D_OBJ) $(NVM_LIB)
	$(CC) $^  -o $@ ${INCLUDE_PATHS} $(CFLAGS) $(LDFLAGS) -lpthread $(GCOV_FLAGS)

clean:
	rm -rf $(OBJECTS) *.gcno *.a *_test $(TEST_OBJ) $(all_libs) *.so* $(all_tests) $(NVM_DAEMON) ${SE_VER_FILE} $(STAGE_DIR)

she_doc: include/she/she_api.h
	rm -rf doc/latex/
	doxygen doc/she/SECO_Doxyfile
	make -C ./doc/latex pdf
	cp doc/latex/refman.pdf doc/seco_she_api_document.pdf
	rm -rf doc/latex/

hsm_doc_ele: include/hsm/hsm_api.h
	rm -rf doc/latex/
	rm -rf doc/rtf/
	doxygen doc/hsm/ELE_Doxyfile
	make -C ./doc/latex pdf
	cp doc/latex/refman.pdf doc/ele_hsm_api_document.pdf
	cp doc/rtf/refman.rtf doc/ele_hsm_api_document.rtf
	rm -rf doc/latex/
	rm -rf doc/rtf/

hsm_doc_seco: include/hsm/hsm_api.h
	rm -rf doc/latex/
	doxygen doc/hsm/SECO_Doxyfile
	make -C ./doc/latex pdf
	cp doc/latex/refman.pdf doc/seco_hsm_api_document.pdf
	rm -rf doc/latex/

install: libs
	mkdir -p $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	$(foreach i, $(LIB_NAMES),\
		ln -s -f $(i).$(SO_EXT) $(i).so.$(MAJOR_VER); \
		ln -s -f $(i).so.$(MAJOR_VER) $(i).so; \
		cp -av --no-preserve=ownership "$(i).$(SO_EXT)" "$(i).so.$(MAJOR_VER)" "$(i).so" $(DESTDIR)$(LIBDIR);)
	mkdir -p $(DESTDIR)$(BINDIR)
	$(prepare_seco_stage_files)
	$(EXPORT_NVM_DAEMON)
	mkdir -p $(DESTDIR)$(SYSTEMD_DIR)
	$(EXPORT_SYSTEMD_NVM_SERVICE)
	$(EXPORT_NVMD_CONF_FILE)
	mkdir -p $(DESTDIR)$(TARGET_README_DIR)
	cp README $(DESTDIR)$(TARGET_README_DIR)
	$(INCLUDE_HEADERS_CP)
	$(NVMD_CONFIG_SCRIPT_CP)
	$(prepare_v2x_stage_files)
	$(EXPORT_V2X_NVM_DAEMON)
	$(EXPORT_V2X_SYSTEMD_NVM_SERVICE)
	$(EXPORT_V2X_NVMD_CONF_FILE)

install_tests: install tests
	mkdir -p $(DESTDIR)$(BINDIR)
	cp $(all_tests) $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(TEST_VECTOR_DEFAULT_DIR)
	cp -r $(TEST_COMMON_TV_PATH) $(DESTDIR)$(TEST_VECTOR_DEFAULT_DIR)

install_version: .git
	echo "#ifndef SE_VERSION_H" > ${SE_VER_FILE}
	echo "#define SE_VERSION_H" >> ${SE_VER_FILE}
	echo "#define LIB_COMMIT_ID \"$(shell git rev-parse HEAD)\"" >> ${SE_VER_FILE}
	cat se_version.txt >> ${SE_VER_FILE}
	echo "#endif" >> ${SE_VER_FILE}

clean_ver_hfile:
	rm -f ${SE_VER_FILE}
