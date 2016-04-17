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
#include "crypto/tweetnacl.h"
#include "crypto/randombytes.h"
#include "bsdcompat/compat.h"

int
jf_encrypt(FILE *infile, FILE *key, FILE *skey, char *filename)
{
	unsigned long long pad_ptext_len, ptext_size, ctext_size = 0;
	unsigned char *pad_ptext_buf, *ptext_buf, *ctext_buf = NULL;
	unsigned char key_buf[PUBKEYBYTES];
	unsigned char skey_buf[SECKEYBYTES];
	unsigned char nonce[NONCEBYTES];
	FILE *outfile = NULL;

	randombytes(nonce, NONCEBYTES);

	/* Get input file size */
	ptext_size = get_size(infile);

	/* Create buffer for input file and close infile */
	if ((ptext_buf = malloc(ptext_size)) == NULL)
		err(1, "Error creating ptext buffer");
	fread(ptext_buf, 1, ptext_size, infile);
	fclose(infile);

	pad_ptext_len = (ptext_size + ZEROBYTES);
	if ((pad_ptext_buf = malloc(pad_ptext_len)) == NULL)
		err(1, "couldn't allocate pad ptext buf");
	memset(pad_ptext_buf, 0, ZEROBYTES);
	memcpy(pad_ptext_buf + ZEROBYTES, ptext_buf, ptext_size);

	safer_free(ptext_buf, ptext_size);

	/* Get ctext size and create buffer. */
	ctext_size = (pad_ptext_len + NONCEBYTES);
	if ((ctext_buf = malloc(ctext_size)) == NULL)
		err(1, "Error creating ctext buffer");
	memcpy(ctext_buf, nonce, NONCEBYTES); 

	/* Read in public key */
	fread(key_buf, 1, sizeof(key_buf), key);
	fclose(key);

	fread(skey_buf, 1, sizeof(skey_buf), skey);
	fclose(skey);

	/* Encrypt */
	if (crypto_box(ctext_buf + NONCEBYTES, pad_ptext_buf, pad_ptext_len,
	    nonce, key_buf, skey_buf) != 0)
		err(1, "Error encrypting data");

	/* Zero and free ptext buffer */
	safer_free(pad_ptext_buf, pad_ptext_len);

	/* Append extension to filename */
	if (strlcat(filename, EXT, FILENAME_SIZE) >= FILENAME_SIZE)
		errx(1, "Filename too long");

	/* Write ctext to disk and free ctext buffer */
	write_file(outfile, ctext_buf, ctext_size, filename);
	free(ctext_buf);

	return (0);
}
