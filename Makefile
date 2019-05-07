
all: she_test she_start_storage_manager she_lib.a she_storage.a hsm_lib.a

CFLAGS = -Werror

ifdef COVERAGE
GCOV_FLAGS=-fprofile-arcs -ftest-coverage
endif

# SHE implementation
she_lib.o: src/she_lib.c
	$(CC) $^  -c -o $@ -I include $(CFLAGS) $(GCOV_FLAGS)

# HSM
hsm_lib.o: src/hsm_lib.c
	$(CC) $^  -c -o $@ -I include -I include/hsm $(CFLAGS) $(GCOV_FLAGS)

# SHE storage implementation
she_storage.o: src/she_storage.c
	$(CC) $^  -c -o $@ -I include $(CFLAGS) $(GCOV_FLAGS)

# HSM storage implementation
hsm_storage.o: src/hsm_storage.c
	$(CC) $^  -c -o $@ -I include -I include/hsm $(CFLAGS) $(GCOV_FLAGS)

# SHE lib
she_lib.a: she_lib.o
	$(AR) rcs $@ $^

# HSM lib
hsm_lib.a: hsm_lib.o
	$(AR) rcs $@ $^

# SHE storage lib
she_storage.a: she_storage.o
	$(AR) rcs $@ $^

#SHE test components
ifdef DEBUG
DEFINES=-DDEBUG
endif

hsm_test: hsm_lib.o hsm_storage.o test/hsm/hsm_test.c
	$(CC) $^  -o $@ -I include -I include/hsm $(CFLAGS) -lpthread -lz $(DEFINES) $(GCOV_FLAGS)

TEST_OBJ=$(patsubst %.c,%.o,$(wildcard test/src/*.c))

test/src/%.o: test/src/%.c 
	$(CC) $^  -c -o $@ -I include -I test/src $(CFLAGS) $(DEFINES)

test/she_start_storage_manager/%.o: test/she_start_storage_manager/%.c
	$(CC) $^  -c -o $@ -I include -I test/src $(CFLAGS) $(DEFINES)

#SHE test app
she_test: she_lib.o she_storage.o $(TEST_OBJ) include/she_api.h
	$(CC) $^  -o $@ -I include $(CFLAGS) -lpthread -lz $(DEFINES) $(GCOV_FLAGS)

she_start_storage_manager: she_lib.o she_storage.o test/she_start_storage_manager/she_start_storage_manager.o include/she_api.h
	$(CC) $^  -o $@ -I include $(CFLAGS) -lpthread -lz $(DEFINES) $(GCOV_FLAGS)

clean:
	rm -rf she_test she_lib.o she_storage.o she_lib.a she_storage.a *.gcno she_start_storage_manager $(TEST_OBJ)

she_doc: include/she_api.h include/she_storage.h
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
