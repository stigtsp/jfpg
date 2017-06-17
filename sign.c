/*
 * Copyright (c) 2016 Joe Fierro <joseph.fierro@runbox.com>
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
#include "defines.h"
#include "base64.h"
#include "tweetnacl.h"
#include "compat.h"
#include "utils.h"

void
jf_sign(FILE *infile, FILE *fd_sign_sk, char *filename)
{
	unsigned long long mlen, smlen = 0;
	unsigned char *m, *sm = NULL;
	
	unsigned char sign_sk[SIGNSKEYBYTES + ZEROBYTES];
	FILE *outfile = NULL;

	decrypt_key(sign_sk, fd_sign_sk);
	fclose(fd_sign_sk);

	/* Get sizes of message and signed message */
	mlen = get_size(infile);
	smlen = mlen + crypto_sign_BYTES;

	/* Create buffers for message and signed message */
	if ((m = malloc(mlen)) == NULL)
		err(1, "Error creating message buffer");
	if ((sm = malloc(smlen)) == NULL)
		err(1, "Error creating signed message buffer");

	/* Read in file to m */
	if (fread(m, 1, mlen, infile) != mlen)
		errx(1, "Error reading in infile");
	fclose(infile);

	/* Sign message m and place results in sm */
	if ((crypto_sign(sm, &smlen, m, mlen, sign_sk + ZEROBYTES)) != 0)
		errx(1, "Error signing");

	/* Zap secret key */
	explicit_bzero(sign_sk, sizeof(sign_sk));
	free(m);

	/* Append extension to filename */
	if (jf_strlcat(filename, SIGNEXT, FILENAME_SIZE) >= FILENAME_SIZE)
		errx(1, "Filename too long");

	/* Write file */
	write_file(outfile, sm, smlen, filename);
	free(sm);
	printf("Created signed file \"%s\"\n", filename);
} 
