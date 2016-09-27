/*
 * Copyright (c) 2016 Joe Fierro <jsf122 at scarletmail dot rutgers dot edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "base64.h"
#include "../bsdcompat/compat.h"
#include "../defines.h"
#include "../crypto/tweetnacl.h"

void
get_keys(unsigned char *pk, unsigned char *sk, FILE *fd_pk, FILE *fd_sk)
{
	int b64len = encode_len(PUBKEYBYTES);
	unsigned char b64_pk[b64len];
	unsigned char b64_sk[b64len];

	if (fread(b64_pk, 1, b64len, fd_pk) != b64len - 1)
		errx(1, "could not read in base64 pubkey");
	if (fread(b64_sk, 1, b64len, fd_sk) != b64len - 1)
		errx(1, "could not read in base64 secret key");
	fclose(fd_pk);
	fclose(fd_sk);

	b64_pton(b64_pk, pk, PUBKEYBYTES);
	b64_pton(b64_sk, sk, SECKEYBYTES);
	explicit_bzero(b64_sk, sizeof(b64_sk));
}
