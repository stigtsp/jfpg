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

#ifdef __linux__
#include <stdint.h>
#endif

#include "jfpg.h"
#include "crypto/tweetnacl.h"

int
jf_verify(FILE *infile, FILE *sign_pk, uint8_t *filename)
{
	uint64_t mlen, smlen = 0;
	uint8_t *m, *sm = NULL;
	uint8_t sign_pk_buf[SIGNPKEYBYTES];
	FILE *outfile = NULL;	

	fread(sign_pk_buf, 1, sizeof(sign_pk_buf), sign_pk);
	fclose(sign_pk);

	smlen = get_size(infile);
	mlen = smlen - crypto_sign_BYTES;

	if ((m = malloc(smlen)) == NULL)
		err(1, "error creating message buffer");
	if ((sm = malloc(smlen)) == NULL)
		err(1, "error creating signed message buffer");

	fread(sm, 1, smlen, infile);
	fclose(infile);
	
	if ((crypto_sign_open(m, &mlen, sm, smlen, sign_pk_buf)) != 0)
		errx(1, "error verifying signature");
	free(sm);

	write_file(outfile, m, mlen, filename); 
	return (0);
} 
