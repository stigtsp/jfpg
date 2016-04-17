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

#include "jfpg.h"
#include "crypto/tweetnacl.h"
#include "bsdcompat/compat.h"

int
jf_sign(FILE *infile, FILE *sign_sk, char *filename)
{
	unsigned long long mlen, smlen = 0;
	unsigned char *m, *sm = NULL;
	unsigned char sign_sk_buf[SIGNSKEYBYTES];
	FILE *outfile = NULL;	

	fread(sign_sk_buf, 1, sizeof(sign_sk_buf), sign_sk);
	fclose(sign_sk);

	mlen = get_size(infile);
	smlen = mlen + crypto_sign_BYTES;

	if ((m = malloc(mlen)) == NULL)
		err(1, "error creating message buffer");
	if ((sm = malloc(smlen)) == NULL)
		err(1, "error creating signed message buffer");

	fread(m, 1, mlen, infile);
	fclose(infile);
 
	if ((crypto_sign(sm, &smlen, m, mlen, sign_sk_buf)) != 0)
		errx(1, "error signing");
	explicit_bzero(sign_sk_buf, sizeof(sign_sk_buf));
	free(m);

	write_file(outfile, sm, smlen, filename); 
	return (0);
} 
