CC = cc 

WARNFLAGS = -Wall -Werror -Wformat-security

SECFLAGS = -fstack-protector-all -fPIC -fPIE -D_FORTIFY_SOURCE=2 

CFLAGS = $(WARNFLAGS) $(SECFLAGS) -O2
 
jfpg: bsdcompat/explicit_bzero.c bsdcompat/strlcat.c bsdcompat/strlcpy.c \
      crypto/tweetnacl.c crypto/randombytes.c  \
      util/get_size.c util/safer_free.c util/write_file.c \
      encrypt.c decrypt.c newkey.c sign.c verify.c main.c \

	$(CC) $(CFLAGS) bsdcompat/explicit_bzero.c bsdcompat/strlcat.c bsdcompat/strlcpy.c \
	    crypto/tweetnacl.c crypto/randombytes.c encrypt.c decrypt.c newkey.c sign.c \
	    verify.c util/get_size.c util/safer_free.c util/write_file.c main.c -o jfpg 
