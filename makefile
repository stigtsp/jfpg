CC = cc

WARNFLAGS = -Wall -Wformat-security

SECFLAGS = -fstack-protector-all -fPIC -fPIE -D_FORTIFY_SOURCE=2 

IFLAGS = -Iinclude

LFLAGS = -pthread

CFLAGS = $(WARNFLAGS) $(SECFLAGS) $(IFLAGS) $(LFLAGS) -O1

SRC = bsdcompat/explicit_bzero.c bsdcompat/strlcat.c bsdcompat/strlcpy.c
SRC += bsdcompat/strtonum.c bsdcompat/readpassphrase.c
SRC += crypto/tweetnacl.c crypto/randombytes.c
SRC += crypto/argon2/argon2.c crypto/argon2/opt.c
SRC += crypto/argon2/core.c crypto/argon2/encoding.c
SRC += crypto/argon2/thread.c crypto/argon2/blake2/blake2b.c
SRC += utils/base64.c utils/utils.c
SRC += encrypt.c decrypt.c newkey.c symops.c sign.c verify.c main.c

 
jfpg: $(SRC)
		$(CC) $(CFLAGS) $(SRC) -o jfpg
