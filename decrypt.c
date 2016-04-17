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
#include <string.h>
#include <stdlib.h>

#include "jfpg.h"
#include "crypto/tweetnacl.h"
#include "bsdcompat/compat.h"

int
jf_decrypt(FILE *infile, FILE *key, FILE *skey, unsigned char *filename)
{
	unsigned long long ptext_size, ctext_size = 0;
	unsigned char *ctext_buf, *ptext_buf = NULL;
	unsigned char key_buf[PUBKEYBYTES];
	unsigned char skey_buf[SECKEYBYTES];
	FILE *outfile = NULL;

	/* Get input file size */
	ctext_size = get_size(infile);

	/* Create buffer for ctext */
	if ((ctext_buf = malloc(ctext_size)) == NULL)
		err(1, "Error creating ctext buffer");
	fread(ctext_buf, 1, ctext_size, infile);
	fclose(infile);

	/* Get ptext size and create ptext buffer */
	ptext_size = (ctext_size - crypto_box_NONCEBYTES);
	if ((ptext_buf = malloc(ptext_size)) == NULL)
		err(1, "Error creating ptext_buf");

	/* Read public key into buffer */
	fread(key_buf, 1, PUBKEYBYTES, key);
	fclose(key);

	/* Read secret key */
	fread(skey_buf, 1, SECKEYBYTES, skey);
	fclose(skey);

	/* Decrypt data with secret key */
	if (crypto_box_open(ptext_buf, ctext_buf + NONCEBYTES,
	    ctext_size - NONCEBYTES, ctext_buf, key_buf, skey_buf)
	         != 0)
		errx(1, "Error decrypting data");
	explicit_bzero(skey_buf, sizeof(skey_buf));

	/* Free ctext buffer */
	free(ctext_buf);

	/* Strip off file extension */
	filename[strlen(filename) - strlen(EXT)] = 0;

	/* Write ptext to file */
	write_file(outfile, ptext_buf + ZEROBYTES, 
	    ptext_size - ZEROBYTES, filename);

	/* Zero and free ptext */	
	safer_free(ptext_buf, ptext_size);

	return (0);
}
