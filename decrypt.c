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
#include "base64.h"
#include "crypto/tweetnacl.h"
#include "bsdcompat/compat.h"

int
jf_decrypt(FILE *infile, FILE *key, FILE *skey, char *filename)
{
	unsigned long long ptext_size, ctext_size = 0;
	int b64len = 0;
	unsigned char *ctext_buf, *ptext_buf = NULL;

	/* Get base64-encoded size for keys. PUBKEYBYTES
	 * and SECKEYBYTES are the same, so it's ok to use
	 * b64len for both
	*/	
	b64len = Base64encode_len(PUBKEYBYTES);

	char b64_pk[b64len];
	char b64_sk[b64len];

	unsigned char pk[PUBKEYBYTES + 1];
	unsigned char sk[SECKEYBYTES + 1];
	FILE *outfile = NULL;

	/* Read public key into buffer */
	if (fread(b64_pk, 1, sizeof(b64_pk), key) != sizeof(b64_pk))
		errx(1, "error reading in public key");
	fclose(key);

	/* Read secret key */
	if (fread(b64_sk, 1, sizeof(b64_sk), skey) != sizeof(b64_sk))
		errx(1, "error reading in secret key");
	fclose(skey);

	/* Base64 decode both keys */
	if (Base64decode((char *)pk, b64_pk) != sizeof(pk))
		errx(1, "error decoding pubkey"); 
	if (Base64decode((char *)sk, b64_sk) != sizeof(sk))
		errx(1, "error decoding secret key"); 

	/* Zero base64 secret key */
	explicit_bzero(b64_sk, sizeof(b64_sk));

	/* Get input file size */
	ctext_size = get_size(infile);

	/* Create buffer for ctext */
	if ((ctext_buf = malloc(ctext_size)) == NULL)
		err(1, "error creating ctext buffer");
	if (fread(ctext_buf, 1, ctext_size, infile) != ctext_size)
		errx(1, "error reading in ciphertext");
	fclose(infile);

	/* Get ptext size and create ptext buffer */
	ptext_size = (ctext_size - crypto_box_NONCEBYTES);
	if ((ptext_buf = malloc(ptext_size)) == NULL)
		err(1, "error creating ptext_buf");

	/* Decrypt data with secret key */
	if (crypto_box_open(ptext_buf, ctext_buf + NONCEBYTES,
	    ctext_size - NONCEBYTES, ctext_buf, pk, sk)
	         != 0)
		errx(1, "error decrypting data");

	/* Zero secret key */
	explicit_bzero(sk, sizeof(sk));

	/* Free ciphertext buffer */
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