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
#include "crypto/scrypt/crypto_scrypt.h"
#include "bsdcompat/compat.h"
#include "bsdcompat/readpassphrase.h"
#include "util/base64.h"

struct hdr {
	unsigned char nonce[NONCEBYTES];
	unsigned long long padded_len;
	long long rounds;
	unsigned int r;
	unsigned int p;
	int alg;
};

static void asymcrypt(unsigned char *, unsigned char *,
    unsigned long long, unsigned char *, FILE *, FILE *);

static void symcrypt(unsigned char *, unsigned char *, struct hdr *);

static void write_enc(FILE *, struct hdr *, unsigned char *, char *);

void
jf_encrypt(FILE *infile, FILE *key, FILE *skey, char *filename, int alg, long long rounds)
{
	unsigned long long ptext_size, ctext_size = 0;
	unsigned char *pad_ptext_buf, *ptext_buf, *ctext_buf = NULL;
	FILE *outfile = NULL;
	struct hdr *hdr;
	
	hdr = malloc(sizeof(struct hdr));
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
		hdr->r = R;
		hdr->p = P;
		hdr->alg = 2;
		symcrypt(ctext_buf, pad_ptext_buf, hdr);
	} else { 
		errx(1, "don't know what to do");
	}
	safer_free(pad_ptext_buf, hdr->padded_len);

	if (jf_strlcat(filename, EXT, FILENAME_SIZE) >= FILENAME_SIZE)
		errx(1, "filename too long");

	write_enc(outfile, hdr, ctext_buf, filename);
	free(hdr);
	printf("encryption successful\n");
}

void
asymcrypt(unsigned char *ctext_buf, unsigned char *pad_ptext_buf, 
    unsigned long long ptext_size, unsigned char *nonce, FILE *key, FILE *skey)
{

	unsigned char pk[PUBKEYBYTES + 2];
	unsigned char sk[SECKEYBYTES + 2];

	get_keys(pk, sk, key, skey); 

	if (crypto_box(ctext_buf, pad_ptext_buf, ptext_size,
            nonce, pk, sk) != 0)
	 	err(1, "error encrypting data");
	explicit_bzero(sk, sizeof(sk));
	free(ctext_buf);
}

void
symcrypt(unsigned char *ctext_buf, unsigned char *pad_ptext_buf, struct hdr *hdr)
{
	char pass[512];
	char pass2[512];
	unsigned char symkey[SYMKEYBYTES];
	
	if (!readpassphrase("enter passphrase: ", pass, sizeof(pass), RPP_FLAGS))
		err(1, "error getting passphrase");
	if (!readpassphrase("confirm passphrase: ", pass2, sizeof(pass2), RPP_FLAGS))
		err(1, "error confirming passphrase");
	if (strcmp(pass, pass2) != 0)
		errx(1, "passphrases do not match");
	explicit_bzero(pass2, sizeof(pass2));

	if (crypto_scrypt((unsigned char *)pass, strlen(pass), hdr->nonce, sizeof(hdr->nonce),
	    hdr->rounds, hdr->r, hdr->p, symkey, sizeof(symkey)) != 0)
		err(1, "error hashing key");
	explicit_bzero(pass, sizeof(pass));

	if (crypto_secretbox(ctext_buf, pad_ptext_buf, hdr->padded_len,
            hdr->nonce, symkey) != 0)
                err(1, "error encrypting message");
	explicit_bzero(symkey, sizeof(symkey));
	free(ctext_buf);
}

void
write_enc(FILE *outfile, struct hdr *hdr, unsigned char *ctext_buf, char *filename)
{
	unsigned int b64_ctext_len = Base64encode_len(hdr->padded_len);
	unsigned int b64_hdr_len = Base64encode_len(sizeof(struct hdr));
	unsigned char b64_hdr[b64_hdr_len];
	unsigned char *b64_ctext_buf = NULL;
	Base64encode((char *)b64_hdr, (char *)hdr, sizeof(struct hdr));

	if ((b64_ctext_buf = malloc(b64_ctext_len)) == NULL)
		errx(1, "couldn't allocate base64 ciphertext buf");
	Base64encode((char *)b64_ctext_buf, (char *)ctext_buf, hdr->padded_len);

	outfile = fopen(filename, "w");
        fwrite(b64_hdr, sizeof(b64_hdr), 1, outfile);
        fwrite(b64_ctext_buf, b64_ctext_len, 1, outfile);
	fclose(outfile);
	free(b64_ctext_buf);
}
