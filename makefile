CC = cc

WARNFLAGS = -Wall -Wformat-security

SECFLAGS = -fstack-protector-all -fPIC -fPIE -D_FORTIFY_SOURCE=2 

LFLAGS = -lpthread

CFLAGS = $(WARNFLAGS) $(SECFLAGS) $(LFLAGS) -O3
 
jfpg: bsdcompat/explicit_bzero.c bsdcompat/strlcat.c bsdcompat/strlcpy.c \
	bsdcompat/strtonum.c bsdcompat/readpassphrase.c \
	crypto/tweetnacl.c crypto/randombytes.c \
	crypto/argon2/argon2.c crypto/argon2/ref.c \
	crypto/argon2/core.c crypto/argon2/encoding.c \
	crypto/argon2/thread.c crypto/argon2/blake2/blake2b.c \
	util/base64.c util/read_infile.c util/get_size.c util/safer_free.c util/write_file.c \
	util/get_keys.c util/base64-utils.c util/decrypt_key.c \
	encrypt.c decrypt.c newkey.c symops.c sign.c verify.c main.c \

		$(CC) $(CFLAGS) -lpthread bsdcompat/explicit_bzero.c bsdcompat/strlcat.c bsdcompat/strlcpy.c \
        	    bsdcompat/strtonum.c bsdcompat/readpassphrase.c \
		    crypto/tweetnacl.c crypto/randombytes.c \
        	    crypto/argon2/argon2.c crypto/argon2/ref.c \
		    crypto/argon2/core.c crypto/argon2/encoding.c \
		    crypto/argon2/thread.c crypto/argon2/blake2/blake2b.c \
		    util/base64.c util/read_infile.c util/get_size.c util/safer_free.c util/write_file.c \
        	    util/get_keys.c util/base64-utils.c util/decrypt_key.c \
		    encrypt.c decrypt.c newkey.c symops.c sign.c verify.c main.c -lm -o jfpg
