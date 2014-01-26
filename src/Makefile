SRC=$(wildcard *.c)
OBJ=$(addprefix ./obj/,$(SRC:.c=.o))
EX=$(addprefix ./bin/,$(SRC:.c=))

LIBTOOL := libtool

INCLUDE_DIRS := $(MAIN_DIR)/imports/cyassl/
LIBRARY_DIRS := $(MAIN_DIR)/imports/cyassl/src/.libs/
LA_FILE := $(MAIN_DIR)/imports/cyassl/src/.libs/libcyassl.a
LIBRARIES := cyassl

CFLAGS += -Wno-pragmas -Wall -Wno-strict-aliasing -Wextra -Wunknown-pragmas --param=ssp-buffer-size=1 -Waddress -Warray-bounds -Wbad-function-cast -Wchar-subscripts -Wcomment -Wfloat-equal -Wformat-security -Wformat=2 -Wmissing-field-initializers -Wmissing-noreturn -Wmissing-prototypes -Wnested-externs -Wnormalized=id -Woverride-init -Wpointer-arith -Wpointer-sign -Wredundant-decls -Wshadow -Wsign-compare -Wstrict-overflow=1 -Wswitch-enum -Wundef -Wunused -Wunused-result -Wunused-variable -Wwrite-strings -fwrapv
CFLAGS += -g -O0

LDIFLAGS += $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
LDLFLAGS += $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDLFLAGS += $(foreach library,$(LIBRARIES),-l$(library))

all: $(OBJ) $(EX) test-certs

test-certs:
	mkdir -p test-certs
	ssh-keygen -q -N '' -b 1024 -m PEM -f ./test-certs/test_cert

./bin/% : %.c
	@-mkdir -p $(dir $@)
	@#$(LIBTOOL) --mode=link --tag=CC $(CC) $(CFLAGS) $(OBJ) -o $@ $(LA_FILE)
	$(CC) $(CFLAGS) $(LDIFLAGS) $(LDLFLAGS) $< -o $@

./obj/%.o : %.c
	@-mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDIFLAGS) -c $< -o $@

clean:
	rm -rf ./bin
	rm -rf ./obj
	rm -rf ./test-certs

