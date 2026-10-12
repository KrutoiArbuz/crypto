CC ?= cc
PYTHON ?= python3
CPPFLAGS ?=
CFLAGS ?= -O2
LDFLAGS ?=
LDLIBS ?=
WARNINGS = -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2
OBJECTS = build/main.o build/sha3.o

.PHONY: all test sanitize demo clean

all: build/sha3sum

build:
	mkdir -p build

build/%.o: src/%.c src/sha3.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -c $< -o $@

build/sha3sum: $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LDLIBS) -o $@

test: build/sha3sum
	$(PYTHON) tests/test_sha3.py --binary build/sha3sum

build/sha3sum-sanitize: src/main.c src/sha3.c src/sha3.h | build
	$(CC) $(CPPFLAGS) $(WARNINGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer src/main.c src/sha3.c $(LDFLAGS) $(LDLIBS) -o $@

sanitize: build/sha3sum-sanitize
	$(PYTHON) tests/test_sha3.py --binary build/sha3sum-sanitize

demo: build/sha3sum
	$(PYTHON) scripts/demo.py

clean:
	$(RM) $(OBJECTS) build/sha3sum build/sha3sum-sanitize
