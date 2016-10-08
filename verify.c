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
#include <string.h>

#include "jfpg.h"
#include "defines.h"
#include "tweetnacl.h"
#include "base64.h"
#include "utils.h"

void
jf_verify(FILE *infile, FILE *fd_sign_pk, char *filename)
{
	unsigned long long mlen, smlen = 0;
	unsigned char *m, *sm = NULL;
	int b64len = 0;

	/* Get size for base64-encoded pub key */
	b64len = encode_len(SIGNPKEYBYTES);

	char b64_sign_pk[b64len];
	unsigned char sign_pk[SIGNPKEYBYTES];
	FILE *outfile = NULL;	

	/* Read in pub key */
	if (fread(b64_sign_pk, 1, b64len, fd_sign_pk)
	    != b64len - 1)
		errx(1, "error reading in public key");
	fclose(fd_sign_pk);

	/* Base64 decode pub key */
	b64_pton(b64_sign_pk, sign_pk, SIGNPKEYBYTES);

	/* Get sizes for signed message and message */
	smlen = get_size(infile);
	mlen = smlen - crypto_sign_BYTES;

	/* Create message and signed message buffers */
	if ((m = malloc(smlen)) == NULL)
		err(1, "error creating message buffer");
	if ((sm = malloc(smlen)) == NULL)
		err(1, "error creating signed message buffer");

	/* Read in file to sm */
	if (fread(sm, 1, smlen, infile) != smlen)
		errx(1, "error reading in infile");
	fclose(infile);
	
	/* Verify sig on sm and place results into m */
	if ((crypto_sign_open(m, &mlen, sm, smlen, sign_pk)) != 0)
		errx(1, "error verifying signature");
	free(sm);

	/* Strip extension */
	filename[strlen(filename) - strlen(SIGNEXT)] = 0;

	/* Write m to file */
	write_file(outfile, m, mlen, filename);
	free(m);
	printf("good signature\n");
} 
