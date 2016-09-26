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
#include "symops.h"
#include "crypto/tweetnacl.h"
#include "bsdcompat/compat.h"
#include "util/utils.h"

static void asymcrypt(unsigned char *, unsigned char *,
    unsigned long long, unsigned char *, FILE *, FILE *);

static void write_enc(FILE *, struct hdr *, unsigned char *, char *);

void
jf_encrypt(FILE *infile, FILE *key, FILE *skey, char *filename, int alg, long long rounds)
{
	unsigned long long ptext_size, ctext_size = 0;
	unsigned char *pad_ptext_buf, *ptext_buf, *ctext_buf = NULL;
	FILE *outfile = NULL;
	struct hdr *hdr = NULL;
	
	hdr = malloc(sizeof(struct hdr));
	if (hdr == NULL)
		err(1, "error allocating hdr");
	randombytes(hdr->nonce, NONCEBYTES);

	ptext_size = get_size(infile);
	if ((ptext_buf = malloc(ptext_size)) == NULL)
		err(1, "error allocating ptext_buf");
	read_infile(infile, ptext_buf, ptext_size);

	hdr->padded_len = (ptext_size + ZEROBYTES);
	if ((pad_ptext_buf = malloc(hdr->padded_len)) == NULL)
		err(1, "couldn't allocate pad ptext buf");

	/* 0-pad first ZEROBYTES of pad_ptext_buf & copy in message */
	memset(pad_ptext_buf, 0, ZEROBYTES);
	memcpy(pad_ptext_buf + ZEROBYTES, ptext_buf, ptext_size);

	/* Zero and free original plaintext buf */
	safer_free(ptext_buf, ptext_size);

	ctext_size = (hdr->padded_len);
	if ((ctext_buf = malloc(ctext_size)) == NULL)
		err(1, "error creating ctext buffer");

	if (alg == 1) {
		hdr->rounds = 0;
		hdr->r = 0;
		hdr->p = 0;
		hdr->alg = 1;
		asymcrypt(ctext_buf, pad_ptext_buf, hdr->padded_len,
	    	    hdr->nonce, key, skey);
	} else if (alg == 2) {
		hdr->rounds = rounds;
		hdr->r = SCRYPT_R;
		hdr->p = SCRYPT_P;
		hdr->alg = 2;
		symcrypt(ctext_buf, pad_ptext_buf, hdr);
	} else { 
		errx(1, "don't know what to do");
	}
	safer_free(pad_ptext_buf, hdr->padded_len);

	if (jf_strlcat(filename, EXT, FILENAME_SIZE) >= FILENAME_SIZE)
		errx(1, "filename too long");

	write_enc(outfile, hdr, ctext_buf, filename);
	printf("encryption successful\n");
}

void
asymcrypt(unsigned char *ctext_buf, unsigned char *pad_ptext_buf, 
    unsigned long long ptext_size, unsigned char *nonce, FILE *key, FILE *skey)
{

	unsigned char pk[PUBKEYBYTES];
	unsigned char sk[SECKEYBYTES];

	get_keys(pk, sk, key, skey); 

	if (crypto_box(ctext_buf, pad_ptext_buf, ptext_size,
            nonce, pk, sk) != 0)
	 	err(1, "error encrypting data");
	explicit_bzero(sk, sizeof(sk));
}

void
write_enc(FILE *outfile, struct hdr *hdr, unsigned char *ctext_buf, char *filename)
{
	outfile = fopen(filename, "w");
        fwrite(hdr, sizeof(struct hdr), 1, outfile);
	fwrite(ctext_buf, 1, hdr->padded_len, outfile);
	fclose(outfile);
	free(hdr);
	free(ctext_buf);
}
