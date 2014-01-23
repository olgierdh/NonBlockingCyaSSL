.PHONY: all build_cyassl


MAIN_DIR :=$(shell git rev-parse --show-toplevel)

export MAIN_DIR

all: examples

build_cyassl:
	if [ -f ./imports/cyassl/Makefile ]; then make -C ./imports/cyassl/; else cd ./imports/cyassl && ./autogen.sh && ./configure && make && cd ../../; fi;
	ls ./imports/cyassl/src/.libs/

examples: build_cyassl
	$(MAKE) -C src

clean:
	$(MAKE) -C src clean
	$(MAKE) -C ./imports/cyassl clean
