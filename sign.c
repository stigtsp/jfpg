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
#include "base64.h"
#include "crypto/tweetnacl.h"
#include "bsdcompat/compat.h"

int
jf_sign(FILE *infile, FILE *fd_sign_sk, char *filename)
{
	unsigned long long mlen, smlen = 0;
	unsigned char *m, *sm = NULL;
	int b64signseclen = 0;
	
	/* Get size for base64-encoded secret key */
	b64signseclen = Base64encode_len(SIGNSKEYBYTES);

	char b64_sign_sk[b64signseclen];
	unsigned char sign_sk[SIGNSKEYBYTES + 1];
	FILE *outfile = NULL;	

	/* Read in secret signing key */
	if (fread(b64_sign_sk, 1, sizeof(b64_sign_sk), fd_sign_sk) 
	    != sizeof(b64_sign_sk))
		errx(1, "error reading in secret signing key");
	fclose(fd_sign_sk);

	/* Base64 decode secret signing key */
	if (Base64decode((char *)sign_sk, b64_sign_sk) != sizeof(sign_sk))
		errx(1, "error decoding signing secret key");

	/* Get sizes of message and signed message */
	mlen = get_size(infile);
	smlen = mlen + crypto_sign_BYTES;

	/* Create buffers for message and signed message */
	if ((m = malloc(mlen)) == NULL)
		err(1, "error creating message buffer");
	if ((sm = malloc(smlen)) == NULL)
		err(1, "error creating signed message buffer");

	/* Read in file to m*/
	if (fread(m, 1, mlen, infile) != mlen)
		errx(1, "error reading in infile");
	fclose(infile);

	/* Sign message m and place results in sm */
	if ((crypto_sign(sm, &smlen, m, mlen, sign_sk)) != 0)
		errx(1, "error signing");
	
	/* Zap secret key */
	explicit_bzero(sign_sk, sizeof(sign_sk));
	free(m);

	/* Append extension to filename */
	if (strlcat(filename, SIGNEXT, FILENAME_SIZE) >= FILENAME_SIZE)
		errx(1, "filename too long");

	/* Write file */
	write_file(outfile, sm, smlen, filename); 
	return (0);
} 
