CC = gcc
			CFLAGS= -std=c99 -Wall -Wextra -Wno-missing-field-initializers -D_DEFAULT_SOURCE
	LDFLAGS = -lpcap 

HEADERF := $(wildcard *.h)
SOURCEF := $(wildcard *.c)
OBJECTF := $(patsubst %.c, %.o, $(SOURCEF))

all: ipk-sniffer

ipk-sniffer: $(SOURCEF) $(HEADERF) $(OBJECTF)
	gcc $(CFLAGS) -o ipk-sniffer $(OBJECTF) $(LDFLAGS)

%.o: %.c %.h
	gcc -c $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f ipk-sniffer $(OBJECTF)

cleano:
	rm -f $(OBJECTF)

