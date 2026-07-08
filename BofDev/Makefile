CC       = x86_64-w64-mingw32-gcc
CFLAGS   = -I ../Beacon/include/coff -DBOF -Wall -Werror -O2
SRCS     = $(wildcard *.c)
OBJS     = $(SRCS:.c=.x64.o)

.PHONY: all clean

all: $(OBJS)

%.x64.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.x64.o
