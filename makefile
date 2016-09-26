CC = cc

WARNFLAGS = -Wall -Wformat-security

SECFLAGS = -fstack-protector-all -fPIC -fPIE -D_FORTIFY_SOURCE=2 

CFLAGS = $(WARNFLAGS) $(SECFLAGS) -O3
 
jfpg: bsdcompat/explicit_bzero.c bsdcompat/strlcat.c bsdcompat/strlcpy.c \
	bsdcompat/strtonum.c bsdcompat/readpassphrase.c \
	crypto/tweetnacl.c crypto/randombytes.c \
	crypto/scrypt/crypto_scrypt-ref.c crypto/scrypt/sha256.c \
	util/base64.c util/read_infile.c util/get_size.c util/safer_free.c util/write_file.c \
	util/get_keys.c util/base64-utils.c \
	encrypt.c decrypt.c newkey.c symops.c sign.c verify.c main.c \

		$(CC) $(CFLAGS) bsdcompat/explicit_bzero.c bsdcompat/strlcat.c bsdcompat/strlcpy.c \
        	    bsdcompat/strtonum.c bsdcompat/readpassphrase.c \
		    crypto/tweetnacl.c crypto/randombytes.c \
        	    crypto/scrypt/crypto_scrypt-ref.c crypto/scrypt/sha256.c \
		    util/base64.c util/read_infile.c util/get_size.c util/safer_free.c util/write_file.c \
        	    util/get_keys.c util/base64-utils.c \
		    encrypt.c decrypt.c newkey.c symops.c sign.c verify.c main.c -lm -o jfpg
