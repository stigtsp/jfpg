CC = cc

KDF_DIR = crypto/argon2
DESTDIR = /usr
PREFIX = /local

OFLAGS = -O3

KERNEL := $(shell uname -s)

ifeq ($(KERNEL), Darwin)
	OFLAGS = -O0
endif

WARNFLAGS = -Wall -Wformat-security

SECFLAGS = -fstack-protector-all -fPIC -fPIE -D_FORTIFY_SOURCE=2 

IFLAGS = -Iinclude

LFLAGS = -pthread

CFLAGS = $(OFLAGS) $(WARNFLAGS) $(SECFLAGS) $(IFLAGS) $(LFLAGS)

SRC = $(KDF_DIR)/argon2.c
SRC += $(KDF_DIR)/core.c $(KDF_DIR)/encoding.c
SRC += $(KDF_DIR)/thread.c $(KDF_DIR)/blake2/blake2b.c

TARGET ?= native
OPTTEST := $(shell $(CC) -Iinclude -march=$(TARGET) $(KDF_DIR)/opt.c -c \
                        -o /dev/null 2>/dev/null; echo $$?)
ifneq ($(OPTTEST), 0)
        SRC += $(KDF_DIR)/ref.c
else
        CFLAGS += -march=$(TARGET)
        SRC += $(KDF_DIR)/opt.c
endif

SRC += bsdcompat/explicit_bzero.c bsdcompat/strlcat.c bsdcompat/strlcpy.c
SRC += bsdcompat/strtonum.c bsdcompat/readpassphrase.c
SRC += crypto/tweetnacl.c crypto/randombytes.c
SRC += utils/base64.c utils/utils.c
SRC += encrypt.c decrypt.c newkey.c symops.c sign.c verify.c main.c

jfpg: $(SRC)
		$(CC) $(CFLAGS) $(SRC) -o jfpg

clean:
		rm jfpg
.PHONY: clean

install: jfpg jfpg.1
	install -m 755 -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 -t $(DESTDIR)$(PREFIX)/bin jfpg
	install -m 755 -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 644 -t $(DESTDIR)$(PREFIX)/share/man/man1 jfpg.1
.PHONY: install
