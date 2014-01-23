SRC=$(wildcard *.c)
OBJ=$(addprefix ./obj/,$(SRC:.c=.o))
EX=$(addprefix ./bin/,$(SRC:.c=))

INCLUDE_DIRS := ../imports/cyassl/
LIBRARY_DIRS := ../imports/cyassl/src/.libs/
LIBRARIES := cyassl

CFLAGS 	+= $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
LDFLAGS += $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDFLAGS += $(foreach library,$(LIBRARIES),-l$(library))

all: $(OBJ) $(EX) test-certs

test-certs:
	mkdir -p test-certs
	ssh-keygen -q -N '' -b 1024 -m PEM -f ./test-certs/test_cert

./bin/% : %.c
	@-mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $@

./obj/%.o : %.c
	@-mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

clean:
	rm -rf ./bin
	rm -rf ./obj
	rm -rf ./test-certs

