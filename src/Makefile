SRC=$(wildcard *.c)
OBJ=$(addprefix ./obj/,$(SRC:.c=.o))
EX=$(addprefix ./bin/,$(SRC:.c=))

all: $(OBJ) $(EX)

./bin/% : %.c
	@-mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(OBJ) -o $@

./obj/%.o : %.c
	@-mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf ./bin
	rm -rf ./obj

