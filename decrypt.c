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
#include "crypto/scrypt/crypto_scrypt.h"
#include "bsdcompat/compat.h"

struct hdr {
        unsigned char nonce[NONCEBYTES];
        unsigned long long padded_len;
	long long rounds;
	unsigned int r;
	unsigned int p;
	int alg;
};

static void asymdecrypt(unsigned char *, unsigned char *, unsigned long long,
    unsigned char *, FILE *, FILE *);

static void symdecrypt(unsigned char *, unsigned char *, struct hdr *);

int
jf_decrypt(FILE *infile, FILE *key, FILE *skey, char *filename)
{
	unsigned char *ctext_buf, *ptext_buf = NULL;
	FILE *outfile = NULL;
	struct hdr *hdr;
	
	hdr = malloc(sizeof(struct hdr));
	if (fread(hdr, 1, sizeof(struct hdr), infile) != sizeof(struct hdr))
		err(1, "error reading in header");;
	
	if ((ctext_buf = malloc(hdr->padded_len)) == NULL)
		err(1, "error allocating ctext_buf");
	read_infile(infile, ctext_buf, hdr->padded_len);

	if ((ptext_buf = malloc(hdr->padded_len)) == NULL)
		err(1, "error creating ptext_buf");

	if (hdr->alg == 1) {
		if (key == NULL)
		    errx(1, "must provide a public key");
		if (skey == NULL) 
		    errx(1, "must provide a secret key");
		asymdecrypt(ptext_buf, ctext_buf, hdr->padded_len, hdr->nonce,
	    	key, skey);
	} else if (hdr->alg == 2) {
		symdecrypt(ptext_buf, ctext_buf, hdr);
	} else {
		errx(1, "don't know what to do");
	}
	free(ctext_buf);

	filename[strlen(filename) - strlen(EXT)] = 0;

	outfile = fopen(filename, "wb");
	fwrite(ptext_buf + ZEROBYTES, hdr->padded_len - ZEROBYTES, 1, outfile); 

	safer_free(ptext_buf, hdr->padded_len);
	fclose(outfile);
	return (0);
}

void
asymdecrypt(unsigned char *ptext_buf, unsigned char *ctext_buf,
    unsigned long long ctext_size, unsigned char *nonce, FILE *key, FILE *skey)
{
	unsigned char pk[PUBKEYBYTES + 1];
	unsigned char sk[SECKEYBYTES + 1];

	get_keys(pk, sk, key, skey); 
 
	if (crypto_box_open(ptext_buf, ctext_buf,
            ctext_size, nonce, pk, sk) != 0)
                errx(1, "error decrypting data");
	explicit_bzero(sk, sizeof(sk));
}

void
symdecrypt(unsigned char *ptext_buf, unsigned char *ctext_buf, struct hdr *hdr)
{
	char *pass = NULL;
	unsigned char symkey[crypto_secretbox_KEYBYTES];

	if ((pass = (getpass("enter passphrase: ")))  == NULL)
                err(1, "error getting passphrase");

        if (crypto_scrypt((unsigned char *)pass, strlen(pass), hdr->nonce, sizeof(hdr->nonce),
            hdr->rounds, hdr->r, hdr->p, symkey, sizeof(symkey)) != 0)
                err(1, "error hashing key");
        explicit_bzero(pass, sizeof(pass));

        if (crypto_secretbox_open(ptext_buf, ctext_buf, hdr->padded_len,
            hdr->nonce, symkey) != 0)
                errx(1, "error decrypting data");
        explicit_bzero(symkey, sizeof(symkey));
}
