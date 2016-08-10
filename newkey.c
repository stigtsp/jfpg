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

#include "jfpg.h"
#include "util/base64.h"
#include "crypto/tweetnacl.h"
#include "bsdcompat/compat.h"

static void name_keys(char *, char *, char *,
    char *, char *);

void
jf_newkey(char *id)
{
	
	int b64len, b64signseclen = 0;
	unsigned char pk[PUBKEYBYTES];
	unsigned char sk[SECKEYBYTES];
	unsigned char sign_sk[SIGNSKEYBYTES];
	unsigned char sign_pk[SIGNPKEYBYTES];
	
	/* Get sizes of base64-encoded keys. PUBKEYBYTES
	 * and SECKEYBYTES are the same, so it's ok to use b64len
	 * for both.
	*/
	b64len = Base64encode_len(PUBKEYBYTES);
	b64signseclen = Base64encode_len(SIGNSKEYBYTES);

	char b64_pk[b64len];
	char b64_sk[b64len];
	char b64_sign_sk[b64signseclen];
	char b64_sign_pk[b64len];
	
	char pk_name[B64NAMESIZE];
	char sk_name[B64NAMESIZE];
	char sign_sk_name[B64NAMESIZE];
	char sign_pk_name[B64NAMESIZE];
	
	FILE *seckey = NULL;
	FILE *pubkey = NULL;
	FILE *sign_seckey = NULL;
	FILE *sign_pubkey = NULL;

	/* Generate keys and place into buffers */
	if (crypto_box_keypair(pk, sk) == -1)
		err(1, "Error generating keys");
	if (crypto_sign_keypair(sign_pk, sign_sk) != 0)
		err(1, "error generating signing keys");

	name_keys(id, pk_name, sk_name, sign_pk_name, sign_sk_name);

	/* Write secret key to disk, then zero it */	
	if (Base64encode(b64_sk, (char *)sk, sizeof(sk)) != sizeof(b64_sk))
		errx(1, "error encoding secret key");
	explicit_bzero(sk, sizeof(sk));
	write_file(seckey, b64_sk, sizeof(b64_sk), sk_name);
	explicit_bzero(b64_sk, sizeof(b64_sk));

	/* Write signing secret key to disk, then zero it */
	if (Base64encode(b64_sign_sk, (char *)sign_sk, sizeof(sign_sk)) != sizeof(b64_sign_sk))
		errx(1, "error encoding signing secret key");
	explicit_bzero(sign_sk, sizeof(sign_sk));
	write_file(sign_seckey, b64_sign_sk, sizeof(b64_sign_sk), sign_sk_name);
	explicit_bzero(b64_sign_sk, sizeof(b64_sign_sk));

	/* Write public key to disk */
	if (Base64encode(b64_pk, (char *)pk, sizeof(pk)) != sizeof(b64_pk))
		errx(1, "error encoding pub key");
	write_file(pubkey, b64_pk, sizeof(b64_pk), pk_name);

	/* Write publick signing key to disk */
	if (Base64encode(b64_sign_pk, (char *)sign_pk, sizeof(sign_pk)) != sizeof(b64_sign_pk))	
		errx(1, "error encoding signing pub key");
	write_file(sign_pubkey, b64_sign_pk, sizeof(b64_sign_pk), sign_pk_name);
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
