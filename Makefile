#for each *.c file one target is compiled
# and diff'ed against *.stdout.txt

CC=gcc
CFLAGS=-g -O0 -std=c99 -Wall -Wextra -Wpedantic
LDFLAGS=-lcapstone
SHELL=/bin/bash
RM="rm"
DIFF="diff"

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
	$(DIFF) -bu5 -rN $<.stdout.txt $@ || $(RM) -f $@

$(TESTS): $(TARGETS)

test: $(TESTS)

clean:
	$(RM) -rf $(TARGETS) $(TESTS)

PHONY: clean all test

