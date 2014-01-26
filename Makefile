.PHONY: all build_cyassl


MAIN_DIR :=$(shell git rev-parse --show-toplevel)

export MAIN_DIR

all: examples

build_cyassl:
	if [ -f ./imports/cyassl/Makefile ]; then make -C ./imports/cyassl/; else cd ./imports/cyassl && ./autogen.sh && ./configure && make && cd ../../; fi;

examples: build_cyassl
	$(shell export LD_LIBRARY_PATH=./imports/cyassl/src/.libs/:$LD_LIBRARY_PATH)
	$(MAKE) -C src

clean:
	$(MAKE) -C src clean
	$(MAKE) -C ./imports/cyassl clean
