#¾²Ì¬¿â1£»¶¯Ì¬¿â0
STATIC=1

CROSS_COMPILE = x86_64-i686-linux-
CFLAGS += -I../include

CC = $(CROSS_COMPILE)gcc
CFLAGS += -g -O2 -Wall 

ifeq ($(STATIC), 1)
LIB=libdispatcher.a
else
LIB=libdispatcher.so
CFLAGS+=-fPIC
endif

LIBOBJ=dis_tbl_ops.o


all: $(LIB)

lib: $(LIB)

%.o: %.c
	$(CC) $(CFLAGS) $(DEFFLAGS) -o $@ -c $<

ifeq ($(STATIC), 1)
$(LIB): $(LIBOBJ)
	$(AR) -rcs $@ $^
else
$(LIB): $(LIBOBJ)
	$(CC) -shared -o $@ $^
endif

clean:
	rm -f $(LIB) $(LIBOBJ)
