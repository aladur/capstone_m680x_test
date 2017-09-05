#for each *.c one target is compiled

CC=gcc
CFLAGS=-g -O0 -std=c99 -Wall -Wextra -Wpedantic
LDFLAGS=-lcapstone
SHELL=/bin/bash
RM="rm"

SRCS    = $(wildcard *.c)
TARGETS = $(patsubst %.c,%,$(SRCS))
TESTS   = $(patsubst %.c,%.tmp,$(SRCS))

all: test

# using a pattern rule to compile/link any *.c file
%: %.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

# another pattern rule to create and compare test outputs
%.tmp: %
	-./$< > $@
	diff -u5 -rN $<.stdout.txt $@

$(TESTS): $(TARGETS)

test: $(TESTS)

clean:
	$(RM) -rf $(TARGETS) $(TESTS)

PHONY: clean all test

