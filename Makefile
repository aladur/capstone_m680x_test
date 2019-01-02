#for each *.c file one target is compiled
# and diff'ed against *.stdout.txt

CC=gcc
CFLAGS=-g -O0 -std=c99 -Wall -Wextra -Wpedantic
LDFLAGS=-lcapstone
SHELL=/bin/bash
RM=rm
DIFF=diff

SRCS    = $(wildcard *.c)
TARGETS = $(patsubst %.c,%,$(SRCS))
TESTS   = $(patsubst %.c,%.tmp,$(SRCS))
OUTPUTREFS = $(patsubst %.c,%.stdout.txt,$(SRCS))

all: test

# using a pattern rule to compile/link any *.c file
%: %.c common.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# another pattern rule to create and compare test outputs
%.tmp: %
	-./$< > $@
	$(DIFF) -bu8 -rN $<.stdout.txt $@ || $(RM) -f $@

# another pattern rule to update all test output reference files (*.stdout.txt)
%.stdout.txt: %
	-./$< > $@

$(TESTS): $(TARGETS)

$(OUTPUTREFS): $(TARGETS)

test: $(TESTS)

update: $(OUTPUTREFS)

clean:
	$(RM) -rf $(TARGETS) $(TESTS)

PHONY: clean all test

