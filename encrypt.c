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
#include "base64.h"
#include "crypto/tweetnacl.h"
#include "crypto/randombytes.h"
#include "bsdcompat/compat.h"

int
jf_encrypt(FILE *infile, FILE *key, FILE *skey, char *filename)
{
	unsigned long long pad_ptext_len, ptext_size, ctext_size = 0;
	unsigned char *pad_ptext_buf, *ptext_buf, *ctext_buf = NULL;
	int b64len = 0;

	b64len = Base64encode_len(PUBKEYBYTES);

	char b64_pk[b64len];
	char b64_sk[b64len];

	unsigned char pk[PUBKEYBYTES + 1];
	unsigned char sk[SECKEYBYTES + 1];
	
	unsigned char nonce[NONCEBYTES];
	FILE *outfile = NULL;

	/* Create random nonce */
	randombytes(nonce, NONCEBYTES);

	/* Read in public key */
	if (fread(b64_pk, 1, sizeof(b64_pk), key) != sizeof(b64_pk))
		errx(1, "error reading in public key");
	fclose(key);

	/* Read in secret key */
	if (fread(b64_sk, 1, sizeof(b64_sk), skey) != sizeof(b64_sk))
		errx(1, "error reading in secret key");
	fclose(skey);

	/* Base64 decode both keys */
	if (Base64decode((char *)pk, b64_pk) != sizeof(pk))
		errx(1, "error decoding pub key"); 
	if (Base64decode((char *)sk, b64_sk) != sizeof(sk))
		errx(1, "error decoding secret key");

	/* Zero base64 secret key */
	explicit_bzero(b64_sk, sizeof(b64_sk));

	/* Get input file size */
	ptext_size = get_size(infile);

	/* Create buffer for input file and close infile */
	if ((ptext_buf = malloc(ptext_size)) == NULL)
		err(1, "error creating ptext buffer");
	if (fread(ptext_buf, 1, ptext_size, infile) != ptext_size)
		errx(1, "error reading into plaintext buf");
	fclose(infile);

	/* Create buffer for 0-padded plaintext */
	pad_ptext_len = (ptext_size + ZEROBYTES);
	if ((pad_ptext_buf = malloc(pad_ptext_len)) == NULL)
		err(1, "couldn't allocate pad ptext buf");

	/* 0-pad plaintext buffer, then copy in message */
	memset(pad_ptext_buf, 0, ZEROBYTES);
	memcpy(pad_ptext_buf + ZEROBYTES, ptext_buf, ptext_size);

	/* Zero and free original plaintext buf */
	safer_free(ptext_buf, ptext_size);

	/* Get ctext size and create buffer. */
	ctext_size = (pad_ptext_len + NONCEBYTES);
	if ((ctext_buf = malloc(ctext_size)) == NULL)
		err(1, "error creating ctext buffer");
	memcpy(ctext_buf, nonce, NONCEBYTES); 

	/* Encrypt */
	if (crypto_box(ctext_buf + NONCEBYTES, pad_ptext_buf, pad_ptext_len,
	    nonce, pk, sk) != 0)
		err(1, "error encrypting data");

	/* Zero and free ptext buffer */
	safer_free(pad_ptext_buf, pad_ptext_len);

	/* Append extension to filename */
	if (strlcat(filename, EXT, FILENAME_SIZE) >= FILENAME_SIZE)
		errx(1, "filename too long");

	/* Write ctext to disk and free ctext buffer */
	write_file(outfile, ctext_buf, ctext_size, filename);
	free(ctext_buf);

	return (0);
}