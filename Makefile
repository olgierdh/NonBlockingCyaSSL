.PHONY: all build_cyassl

all: examples

build_cyassl:
	if [ -f ./imports/cyassl/Makefile ]; then make -C ./imports/cyassl/; else cd ./imports/cyassl && ./autogen.sh && ./configure && make && cd ../../; fi;

examples: build_cyassl
	$(MAKE) -C src

clean:
	$(MAKE) -C src clean
	$(MAKE) -C ./imports/cyassl clean
