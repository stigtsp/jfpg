#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "base64.h"
#include "../bsdcompat/compat.h"
#include "../jfpg.h"
#include "../crypto/tweetnacl.h"

void
get_keys(unsigned char *pk, unsigned char *sk, FILE *fd_pk, FILE *fd_sk)
{
	int b64len = Base64encode_len(PUBKEYBYTES);
	char b64_pk[b64len];
	char b64_sk[b64len];

	if (fread(b64_pk, 1, sizeof(b64_pk), fd_pk) != sizeof(b64_pk))
		errx(1, "could not read in base64 pubkey");
	if (fread(b64_sk, 1, sizeof(b64_sk), fd_sk) != sizeof(b64_sk))
		errx(1, "could not read in base64 secret key");
	fclose(fd_pk);
	fclose(fd_sk);

	if (Base64decode((char *)pk, b64_pk) != PUBKEYBYTES + 1)
		errx(1, "could not decode base64 pubkey");
	if (Base64decode((char *)sk, b64_sk) != PUBKEYBYTES + 1)
		errx(1, "could not decode base64 secret key");
	explicit_bzero(b64_sk, sizeof(b64_sk));
}
