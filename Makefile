all: she_test

all: she_test

CFLAGS = -Werror

# Placeholder for platform specific implementation
platform_lib.o: src/seco_mu_linux.c
	$(CC) $^  -c -o $@ -I include $(CFLAGS)

# SHE implementation
she_lib.o: src/she_lib.c
	$(CC) $^  -c -o $@ -I include $(CFLAGS)

# SHE storage implementation
she_storage.o: src/she_storage.c
	$(CC) $^  -c -o $@ -I include $(CFLAGS)

# SHE storage implementation
messaging.o: src/messaging.c
	$(CC) $^  -c -o $@ -I include $(CFLAGS)

#SHE test components
TEST_OBJ=$(patsubst %.c,%.o,$(wildcard test/src/*.c))

test/src/%.o: test/src/%.c 
	$(CC) $^  -c -o $@ -I include -I test/src $(CFLAGS)

#SHE test app
she_test: she_lib.o she_storage.o platform_lib.o messaging.o $(TEST_OBJ) include/she_api.h
	$(CC) $^  -o $@ -I include $(CFLAGS) -lpthread -lz

clean:
	rm -rf she_test she_lib.o platform_lib.o she_storage.o messaging.o

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
