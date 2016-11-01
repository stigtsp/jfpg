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
#include <string.h>

#include "symops.h"
#include "compat.h"
#include "readpassphrase.h"
#include "argon2.h"
#include "tweetnacl.h"

#define SYMKEYBYTES     crypto_secretbox_KEYBYTES
#define RPP_FLAGS       RPP_REQUIRE_TTY

static void derive_key(struct hdr *, char *, unsigned char *);

void
symcrypt(unsigned char *ctext_buf, unsigned char *pad_ptext_buf, struct hdr *hdr)
{
	char pass[512];
	char pass2[512];
	unsigned char symkey[SYMKEYBYTES];

	if (!readpassphrase("enter new passphrase: ", pass, sizeof(pass), RPP_FLAGS))
		err(1, "error getting passphrase");
        if (!readpassphrase("confirm new passphrase: ", pass2, sizeof(pass2), RPP_FLAGS))
                err(1, "error confirming passphrase");
        if (strcmp(pass, pass2) != 0)
                errx(1, "passphrases do not match");
        explicit_bzero(pass2, sizeof(pass2));
	derive_key(hdr, pass, symkey);
	explicit_bzero(pass, sizeof(pass));

	if (crypto_secretbox(ctext_buf, pad_ptext_buf, hdr->padded_len,
	    hdr->nonce, symkey) != 0)
	err(1, "error encrypting message");
	explicit_bzero(symkey, sizeof(symkey));
}

void
symdecrypt(unsigned char *ptext_buf, unsigned char *ctext_buf, struct hdr *hdr)
{
        char pass[512];
        unsigned char symkey[SYMKEYBYTES];
        if (!readpassphrase("enter passphrase: ", pass, sizeof(pass), RPP_FLAGS))
                err(1, "error getting passphrase");

	derive_key(hdr, pass, symkey);
	explicit_bzero(pass, sizeof(pass));

        if (crypto_secretbox_open(ptext_buf, ctext_buf, hdr->padded_len,
            hdr->nonce, symkey) != 0)
                errx(1, "error decrypting data");
        explicit_bzero(symkey, sizeof(symkey));
}

void
derive_key(struct hdr *hdr, char *pass, unsigned char *symkey)
{
	if (argon2d_hash_raw(hdr->rounds, hdr->mem, hdr->p, pass, strlen(pass), hdr->nonce,
                sizeof(hdr->nonce), symkey, SYMKEYBYTES) != 0)
		errx(1, "argon2 could not derive key");
}
