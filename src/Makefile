SRC=$(wildcard *.c)
OBJ=$(addprefix ./obj/,$(SRC:.c=.o))
EX=$(addprefix ./bin/,$(SRC:.c=))

INCLUDE_DIRS := ../imports/cyassl/
LIBRARY_DIRS := ../imports/cyassl/src/.libs/
LIBRARIES := cyassl

LDIFLAGS += $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
LDLFLAGS += $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDLFLAGS += $(foreach library,$(LIBRARIES),-l$(library))

all: $(OBJ) $(EX) test-certs

test-certs:
	mkdir -p test-certs
	ssh-keygen -q -N '' -b 1024 -m PEM -f ./test-certs/test_cert

./bin/% : %.c
	@-mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDLFLAGS) $(OBJ) -o $@

./obj/%.o : %.c
	@-mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDIFLAGS) -c $< -o $@

clean:
	rm -rf ./bin
	rm -rf ./obj
	rm -rf ./test-certs

