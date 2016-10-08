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
#include "base64.h"
#include "tweetnacl.h"
#include "compat.h"
#include "utils.h"

static void name_keys(char *, char *, char *,
    char *, char *);
static void encrypt_keys(unsigned char *, unsigned char *, 
			 unsigned char *, unsigned char *,
			 struct hdr *, struct hdr *, long long,
			 long long);
void
jf_newkey(char *id, long long rounds, long long mem)
{
	
	int b64len = 0;
	unsigned char pk[PUBKEYBYTES];
	unsigned char sk[SECKEYBYTES + ZEROBYTES];
	unsigned char sign_sk[SIGNSKEYBYTES + ZEROBYTES];
	unsigned char sign_pk[SIGNPKEYBYTES];
	unsigned char sk_crypt[SECKEYBYTES + ZEROBYTES];
	unsigned char sign_sk_crypt[SIGNSKEYBYTES + ZEROBYTES];

	struct hdr *sk_hdr = NULL;
	struct hdr *sign_sk_hdr = NULL;

	/* Get sizes of base64-encoded keys. */ 
	b64len = encode_len(sizeof(pk));

	char b64_pk[b64len];
	char b64_sign_pk[b64len];
	
	char pk_name[B64NAMESIZE];
	char sk_name[B64NAMESIZE];
	char sign_sk_name[B64NAMESIZE];
	char sign_pk_name[B64NAMESIZE];
	
	FILE *seckey = NULL;
	FILE *pubkey = NULL;
	FILE *sign_seckey = NULL;
	FILE *sign_pubkey = NULL;

	/* Ensure secret key buffers are zeroed before key generation */	
	explicit_bzero(sk, sizeof(sk));
	explicit_bzero(sign_sk, sizeof(sign_sk));

	/* Generate keys and place into buffers */
	if (crypto_box_keypair(pk, sk + ZEROBYTES) == -1)
		err(1, "Error generating keys");
	if (crypto_sign_keypair(sign_pk, sign_sk + ZEROBYTES) != 0)
		err(1, "error generating signing keys");

	/* Set up headers for encrypted keys */
	sk_hdr = malloc(sizeof(struct hdr));
	sign_sk_hdr = malloc(sizeof(struct hdr));
	if (sk_hdr == NULL)
		err(1, "error allocating secret key header");
	if (sign_sk_hdr == NULL)
		err(1, "error allocating secret signing key header");

	/* Encrypt secret keys */ 
	encrypt_keys(sk, sk_crypt, sign_sk, sign_sk_crypt, sk_hdr,
		     sign_sk_hdr, rounds, mem);

	/* Zap plaintext secret keys */
	explicit_bzero(sk, sizeof(sk));
	explicit_bzero(sign_sk, sizeof(sign_sk));

	/* Fill in names for keys based on user-supplied ID */
	name_keys(id, pk_name, sk_name, sign_pk_name, sign_sk_name);

	/* Write encrypted secret key to disk, then zero it */	
	seckey = fopen(sk_name, "w");
	fwrite(sk_hdr, sizeof(struct hdr), 1, seckey);
	fwrite(sk_crypt, 1, sizeof(sk_crypt), seckey);
	explicit_bzero(sk_crypt, sizeof(sk_crypt));
	free(sk_hdr);

	/* Write encrypted signing secret key to disk, then zero it */
	sign_seckey = fopen(sign_sk_name, "w");
	fwrite(sign_sk_hdr, sizeof(struct hdr), 1, sign_seckey);
	fwrite(sign_sk_crypt, 1, sizeof(sign_sk_crypt), sign_seckey);
	explicit_bzero(sign_sk_crypt, sizeof(sign_sk_crypt));
	free(sign_sk_hdr);

	/* Write public key to disk */
	if (b64_ntop(pk, sizeof(pk), b64_pk, sizeof(b64_pk)) == -1)
		errx(1, "error encoding pub key");
	write_file(pubkey, b64_pk, strlen(b64_pk), pk_name);

	/* Write publick signing key to disk */
	if (b64_ntop(sign_pk, sizeof(sign_pk), b64_sign_pk, sizeof(b64_sign_pk)) == -1)	
		errx(1, "error encoding signing pub key");
	write_file(sign_pubkey, b64_sign_pk, strlen(b64_sign_pk), sign_pk_name);
}

void
encrypt_keys(unsigned char *sk, unsigned char *sk_crypt, unsigned char *sign_sk,
	     unsigned char *sign_sk_crypt, struct hdr *sk_hdr, struct hdr *sign_sk_hdr,
	     long long rounds, long long mem)
{
	/* Get ready to encrypt curve25519 secret key */
	randombytes(sk_hdr->nonce, sizeof(sk_hdr->nonce));
	sk_hdr->padded_len = SECKEYBYTES + ZEROBYTES;
	sk_hdr->rounds = rounds;
	sk_hdr->mem = mem;
	sk_hdr->p = ARGON2_P;
	sk_hdr->alg = 2;

	/* Encrypt secret key */
	printf("encrypting secret encryption key...\n");
	symcrypt(sk_crypt, sk, sk_hdr);

	/* Get ready to encrypt ed25519 signing key */
	randombytes(sign_sk_hdr->nonce, sizeof(sign_sk_hdr->nonce));
        sign_sk_hdr->padded_len = SIGNSKEYBYTES + ZEROBYTES;
        sign_sk_hdr->rounds = rounds;
        sign_sk_hdr->mem = mem;
        sign_sk_hdr->p = ARGON2_P;
        sign_sk_hdr->alg = 2;

	/* Encrypt signing key */
	printf("\nencrypting secret signing key...\n");
	symcrypt(sign_sk_crypt, sign_sk, sign_sk_hdr);
}
void
name_keys(char *id, char *pk_name, char *sk_name, char *sign_pk_name, 
    char *sign_sk_name)
{
	        /* Zero the buffers for file names */
        memset(pk_name, 0, B64NAMESIZE);
        memset(sk_name, 0, B64NAMESIZE);
        memset(sign_pk_name, 0, B64NAMESIZE);
        memset(sign_sk_name, 0, B64NAMESIZE);

        /* Copy key ID into name buffers */
        memcpy(pk_name, id, strlen(id));
        memcpy(sk_name, id, strlen(id));
        memcpy(sign_sk_name, id, strlen(id));
        memcpy(sign_pk_name, id, strlen(id));

        /* Append rest of key name to the ID */
        if (jf_strlcat(pk_name, PUB, B64NAMESIZE) >= B64NAMESIZE)
                errx(1, "name too long");
        if (jf_strlcat(sk_name, SEC, B64NAMESIZE) >= B64NAMESIZE)
                errx(1, "name too long");
        if (jf_strlcat(sign_pk_name, PUBSIGN, B64NAMESIZE) >=  B64NAMESIZE)
                errx(1, "id too long");
        if (jf_strlcat(sign_sk_name, SECSIGN, B64NAMESIZE) >=  B64NAMESIZE)
                errx(1, "id too long");
}
