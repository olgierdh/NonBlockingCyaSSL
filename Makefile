.PHONY: all

all: build_cyassl
	examples

build_cyassl:
	cd ./imports/cyassl && ./autogen.sh && ./configure && make && cd ../../

examples:
	$(MAKE) -C src

clean:
	$(MAKE) -C src clean
	$(MAKE) -C ./imports/cyassl clean
