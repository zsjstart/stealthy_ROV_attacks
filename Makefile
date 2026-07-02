CC      ?= gcc
CFLAGS  ?= -O3 -march=native -shared -fPIC -Wall
LIB      = native/libbgp.so
SRC      = native/bgp_prop.c

.PHONY: all clean test bench demo

all: $(LIB)

$(LIB): $(SRC)
	$(CC) $(CFLAGS) -o $(LIB) $(SRC)

test: $(LIB)
	python3 tests/test_correctness.py
	python3 tests/test_leak.py

demo: $(LIB)
	python3 examples/demo.py

bench: $(LIB)
	python3 bench/bench_bgp.py

clean:
	rm -f $(LIB)
