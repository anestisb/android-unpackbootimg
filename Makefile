CC      ?= gcc
LD      ?= gcc
DEP_CC  ?= gcc
AR      ?= ar
RANLIB  ?= ranlib
STRIP   ?= strip
CFLAGS  += -O2 -Wall -Werror -Wno-address-of-packed-member
LDFLAGS +=

# libmincrypt
LIB_NAME = mincrypt
SLIB     = lib$(LIB_NAME).a
LIB_SRCS = \
    libmincrypt/dsa_sig.c \
    libmincrypt/p256.c \
    libmincrypt/p256_ec.c \
    libmincrypt/p256_ecdsa.c \
    libmincrypt/rsa.c \
    libmincrypt/sha.c \
    libmincrypt/sha256.c
LIB_OBJS = $(LIB_SRCS:%.c=%.o)
LIB_INCS = -Iinclude

LDFLAGS += -L. -l$(LIB_NAME)

# mkbootimg
MKBOOTIMG_SRCS = mkbootimg.c
MKBOOTIMG_OBJS = $(MKBOOTIMG_SRCS:%.c=%.o)

# unpackbootimg
UNPACKBOOTIMG_SRCS = unpackbootimg.c
UNPACKBOOTIMG_OBJS = $(UNPACKBOOTIMG_SRCS:%.c=%.o)

SRCS = \
    $(MKBOOTIMG_SRCS) \
    $(UNPACKBOOTIMG_SRCS) \
    $(LIB_SRCS)

.PHONY: default all clean

default: all
all: $(LIB_NAME) mkbootimg unpackbootimg

$(LIB_NAME): $(LIB_OBJS)
		$(AR) rc $(SLIB) $(LIB_OBJS)
		$(RANLIB) $(SLIB)

mkbootimg: $(MKBOOTIMG_SRCS)
		$(CC) $(CFLAGS) $(LIB_INCS) -o mkbootimg $< $(LDFLAGS)

unpackbootimg: $(UNPACKBOOTIMG_SRCS)
		$(CC) $(CFLAGS) $(LIB_INCS) -o unpackbootimg $< $(LDFLAGS)

%.o: %.c .depend
		$(CC) -c $(CFLAGS) $(LIB_INCS) $< -o $@

clean:
		$(RM) -f *.o *.a mkbootimg unpackbootimg .depend

ifneq ($(wildcard .depend),)
include .depend
endif

.depend:
		@$(RM) .depend
		@$(foreach SRC, $(SRCS), $(DEP_CC) $(LIB_INCS) $(SRC) $(CFLAGS) -MT $(SRC:%.c=%.o) -MM >> .depend;)
