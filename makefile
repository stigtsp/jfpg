CC = cc

WARNFLAGS = -Wall -Wformat-security

SECFLAGS = -fstack-protector-all -fPIC -fPIE -D_FORTIFY_SOURCE=2 

IFLAGS = -Iinclude

LFLAGS = -pthread

CFLAGS = $(WARNFLAGS) $(SECFLAGS) $(IFLAGS) $(LFLAGS) -O1
 
jfpg: bsdcompat/explicit_bzero.c bsdcompat/strlcat.c bsdcompat/strlcpy.c \
	bsdcompat/strtonum.c bsdcompat/readpassphrase.c \
	crypto/tweetnacl.c crypto/randombytes.c \
	crypto/argon2/argon2.c crypto/argon2/ref.c \
	crypto/argon2/core.c crypto/argon2/encoding.c \
	crypto/argon2/thread.c crypto/argon2/blake2/blake2b.c \
	utils/base64.c utils/utils.c \
	encrypt.c decrypt.c newkey.c symops.c sign.c verify.c main.c \

		$(CC) $(CFLAGS) -lpthread bsdcompat/explicit_bzero.c bsdcompat/strlcat.c bsdcompat/strlcpy.c \
        	    bsdcompat/strtonum.c bsdcompat/readpassphrase.c \
		    crypto/tweetnacl.c crypto/randombytes.c \
        	    crypto/argon2/argon2.c crypto/argon2/ref.c \
		    crypto/argon2/core.c crypto/argon2/encoding.c \
		    crypto/argon2/thread.c crypto/argon2/blake2/blake2b.c \
        	    utils/base64.c utils/utils.c \
		    encrypt.c decrypt.c newkey.c symops.c sign.c verify.c main.c -o jfpg
