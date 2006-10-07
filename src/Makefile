.PHONY: all clean

ARCH:=$(shell uname -m)

SOURCES=$(wildcard *.c)
HEADERS=$(wildcard *.h)
OBJECTS=$(SOURCES:.c=.o)

CFLAGS=-Wall -march=$(ARCH)
LDFLAGS=-lpthread

%.o: %.c
	gcc $(CFLAGS) -c $<

all: gnscd.$(ARCH)

gnscd.$(ARCH): $(OBJECTS)
	gcc $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o gnscd.* .depend

.depend: $(SOURCES) $(HEADERS)
	gcc -MM *.c > .depend

-include .depend
