# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright 2021, 2022, 2023 NXP
#

ELE_PERF ?= 1
CFLAGS := -O1 -Werror -Wformat -fPIC
LDFLAGS =
DESTDIR ?= export
BINDIR ?= /usr/bin
base_libdir ?= lib
LIBDIR ?= /usr/$(base_libdir)
INCLUDEDIR ?= /usr/include
SYSTEMD_DIR ?= /etc/systemd/system
ETC_DIR ?= /etc
TEST_VECTOR_DEFAULT_DIR ?= /usr/share/se/test_vectors
PLAT ?= seco
MAJOR_VER := 1
DEFINES += -DLIB_MAJOR_VERSION=${MAJOR_VER}
NVM_DAEMON := nvm_daemon
NVMD_CONF_FILE := nvmd.conf
SYSTEMD_NVM_SERVICE := nvm_daemon.service
TEST_VECTOR_FNAME ?= test_vectors_*.tv
TEST_BLOB_FNAME ?= *.blob
OPENSSL_PATH ?= ../openssl/

ifdef COVERAGE
GCOV_FLAGS :=-fprofile-arcs -ftest-coverage
endif

PLAT_PATH := src/plat/$(PLAT)
PLAT_COMMON_PATH := src/common
TEST_COMMON_TV_PATH := test/common/test_vectors

INCLUDE_PATHS := -I${PLAT_PATH}/include -I${PLAT_COMMON_PATH}/include -Iinclude -Iinclude/hsm

NVM_OBJECTS := \
	$(PLAT_COMMON_PATH)/nvm/nvm_manager.o \
	$(PLAT_PATH)/nvm_os_abs_linux.o

OBJECTS	:= $(NVM_OBJECTS)\
	$(PLAT_COMMON_PATH)/sab_messaging.o \
	$(PLAT_COMMON_PATH)/sab_common_err.o \
	$(PLAT_COMMON_PATH)/she_lib.o \
	$(PLAT_COMMON_PATH)/hsm_lib.o

include $(PLAT_COMMON_PATH)/sab_msg/sab_msg.mk
include $(PLAT_COMMON_PATH)/hsm_api/hsm_api.mk
include $(PLAT_PATH)/$(PLAT).mk

LIB_NAMES := $(HSM_LIB_NAME) $(NVM_LIB_NAME) $(SHE_LIB_NAME)

SO_EXT := so.${MAJOR_VER}.${MINOR_VER}

NVM_LIB := $(NVM_LIB_NAME).$(SO_EXT)
NVM_LIB_MAJOR := $(NVM_LIB_NAME).so.$(MAJOR_VER)
HSM_LIB := $(HSM_LIB_NAME).$(SO_EXT)
HSM_LIB_MAJOR := $(HSM_LIB_NAME).so.$(MAJOR_VER)
SHE_LIB := $(SHE_LIB_NAME).$(SO_EXT)
SHE_LIB_MAJOR := $(SHE_LIB_NAME).so.$(MAJOR_VER)

all_tests:= $(SHE_TEST) $(HSM_TEST) $(V2X_TEST)
all_libs:= $(SHE_LIB) $(NVM_LIB) $(HSM_LIB)

# Make targets, must need NVM-Daemon to run successfully.
tests: $(all_tests) $(NVM_DAEMON)
libs: $(all_libs) $(NVM_DAEMON)
all: $(all_libs) $(all_tests) $(NVM_DAEMON)

.PHONY: all clean

%.o: %.c
	@echo "  HOSTCC  $<"
	${CC} -c ${CFLAGS} ${GCOV_FLAGS} ${INCLUDE_PATHS} $< -o $@

# SHE lib
$(SHE_LIB): \
	$(PLAT_PATH)/$(PLAT)_utils.o \
	$(PLAT_PATH)/plat_err.o \
	$(PLAT_PATH)/$(PLAT)_os_abs_linux.o \
	$(PLAT_COMMON_PATH)/sab_common_err.o \
	$(PLAT_COMMON_PATH)/she_lib.o \
	$(SAB_MSG_SRC) \
	$(PLAT_COMMON_PATH)/sab_msg/sab_session.o\
	$(HSM_API_SRC) \
	$(PLAT_COMMON_PATH)/sab_messaging.o
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


ifeq ($(ELE_PERF), 1)
DEFINES += -DELE_PERF
endif

CFLAGS += ${DEFINES}
COMMON_TEST_OBJ=$(wildcard test/common/*.c)
COMMON_TEST_INC=-Itest/common/include/

HSM_TEST_OBJ=$(wildcard test/hsm/*.c) $(COMMON_TEST_OBJ)
TEST_CFLAGS = -Wno-deprecated-declarations $(CFLAGS)
TEST_LDFLAGS = -L $(OPENSSL_PATH) -lcrypto $(LDFLAGS) -lcrypto -lpthread
TEST_INCLUDE_PATHS = ${INCLUDE_PATHS} -I$(OPENSSL_PATH)/include
$(HSM_TEST): $(HSM_TEST_OBJ) $(HSM_LIB)
	$(CC) $^  -o $@ ${TEST_INCLUDE_PATHS} ${COMMON_TEST_INC} $(TEST_CFLAGS) $(TEST_LDFLAGS) $(GCOV_FLAGS)

SHE_TEST_OBJ=$(wildcard test/she/src/*.c)
#SHE test app
$(SHE_TEST): $(SHE_TEST_OBJ) $(SHE_LIB) $(NVM_LIB)
	$(CC) $^  -o $@ ${INCLUDE_PATHS} $(CFLAGS) $(LDFLAGS) -lpthread $(GCOV_FLAGS)

V2X_TEST_OBJ=$(wildcard test/v2x/*.c)
$(V2X_TEST): $(V2X_TEST_OBJ) $(HSM_LIB) $(NVM_LIB)
	$(CC) $^  -o $@ ${INCLUDE_PATHS} $(CFLAGS) $(LDFLAGS) -lpthread $(GCOV_FLAGS)

# NVM Daemon
NVM_D_OBJ=$(wildcard src/common/nvm/*.c)
$(NVM_DAEMON): $(NVM_D_OBJ) $(NVM_LIB)
	$(CC) $^  -o $@ ${INCLUDE_PATHS} $(CFLAGS) $(LDFLAGS) -lpthread $(GCOV_FLAGS)

clean:
	rm -rf $(OBJECTS) *.gcno *.a *_test $(TEST_OBJ) $(all_libs) *.so* $(all_tests) $(NVM_DAEMON)

she_doc: include/she_api.h include/nvm.h
	rm -rf doc/latex/
	doxygen doc/she/Doxyfile
	make -C ./doc/latex pdf
	cp doc/latex/refman.pdf doc/she_api_manual.pdf
	rm -rf doc/latex/

hsm_doc: include/hsm/hsm_api.h
	rm -rf doc/latex/
	doxygen doc/hsm/Doxyfile
	make -C ./doc/latex pdf
	cp doc/latex/refman.pdf doc/hsm_api_document.pdf
	rm -rf doc/latex/

install: $(libs)
	mkdir -p $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	$(foreach i, $(LIB_NAMES),\
		ln -s -f $(i).$(SO_EXT) $(i).so.$(MAJOR_VER); \
		ln -s -f $(i).so.$(MAJOR_VER) $(i).so; \
		cp -av --no-preserve=ownership "$(i).$(SO_EXT)" "$(i).so.$(MAJOR_VER)" "$(i).so" $(DESTDIR)$(LIBDIR);)
	mkdir -p $(DESTDIR)$(BINDIR)
	cp $(NVM_DAEMON) $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(SYSTEMD_DIR)
	cp $(PLAT_COMMON_PATH)/nvm/$(SYSTEMD_NVM_SERVICE) $(DESTDIR)$(SYSTEMD_DIR)
	cp $(PLAT_COMMON_PATH)/nvm/$(NVMD_CONF_FILE) $(DESTDIR)$(ETC_DIR)
	cp -a include/* $(DESTDIR)$(INCLUDEDIR)

install_tests: install $(tests)
	mkdir -p $(DESTDIR)$(BINDIR)
	cp $(all_tests) $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(TEST_VECTOR_DEFAULT_DIR)
	cp $(TEST_COMMON_TV_PATH)/$(TEST_VECTOR_FNAME) $(DESTDIR)$(TEST_VECTOR_DEFAULT_DIR)
	cp $(TEST_COMMON_TV_PATH)/$(TEST_BLOB_FNAME) $(DESTDIR)$(TEST_VECTOR_DEFAULT_DIR)
