/*
 * Copyright (c) 2016 Joe Fierro <joseph.fierro@runbox.com>
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

#include <sys/mman.h>

#include <err.h>
#include <string.h>

#include "symops.h"
#include "compat.h"
#include "readpassphrase.h"
#include "argon2.h"
#include "tweetnacl.h"

#define SYMKEYBYTES     crypto_secretbox_KEYBYTES

extern int global_rpp_flags;

static void derive_key(struct hdr *, char *, unsigned char *);

/* https://cryptocoding.net/index.php/Coding_rules */
int cmp_const(const void * a, const void *b, const size_t size)
{
  const unsigned char *_a = (const unsigned char *) a;
  const unsigned char *_b = (const unsigned char *) b;
  unsigned char result = 0;
  size_t i;

  for (i = 0; i < size; i++) {
    result |= _a[i] ^ _b[i];
  }

  return result;
}

void
symcrypt(unsigned char *ctext_buf, unsigned char *pad_ptext_buf, struct hdr *hdr)
{
	char pass[512];
	char pass2[512];
	unsigned char symkey[SYMKEYBYTES];

	/* Read in and confirm passphrase */
	if (!readpassphrase("Enter new passphrase: ", pass, sizeof(pass), global_rpp_flags))
		err(1, "Error getting passphrase");
	if (strlen(pass) == 0)
		errx(1, "Please enter a passphrase");
	if (strlen(pass) < 15)
		warnx("Warning: passphrase is short, but continuing anyway");


	/* Only confirm passphrase if we're requiring a tty. This way we
	 * skip this when using stdin to make it easier to pipe in a passphrase
	 */
	if (global_rpp_flags == RPP_REQUIRE_TTY) {
		if (!readpassphrase("Confirm new passphrase: ", pass2, sizeof(pass2), global_rpp_flags))
                    err(1, "Error confirming passphrase");
        	if (cmp_const(pass, pass2, strlen(pass)) != 0)
                    errx(1, "Passphrases do not match");
        }

	/* Zero the extra passphrase buffer, derive the key, then zero the
	 * other passphrase buffer too
	 */
	explicit_bzero(pass2, sizeof(pass2));
	derive_key(hdr, pass, symkey);
	explicit_bzero(pass, sizeof(pass));

	/* Encrypt */
	if (crypto_secretbox(ctext_buf, pad_ptext_buf, hdr->padded_len,
	    hdr->nonce, symkey) != 0)
		errx(1, "Error encrypting message");

	/* Zero the key */
	explicit_bzero(symkey, sizeof(symkey));
}

void
symdecrypt(unsigned char *ptext_buf, unsigned char *ctext_buf, struct hdr *hdr)
{
        char pass[512];
        unsigned char symkey[SYMKEYBYTES];

	/* Lock passphrase buf */
	if (mlock(pass, sizeof(pass)) !=0 )
		errx(1, "Error locking passphrase buf");

	/* Lock symmetric key buf */
	if (mlock(symkey, sizeof(symkey)) !=0 )
		errx(1, "Error locking symmetric key buf");

	/* Read in passphrase */
	if (!readpassphrase("Enter passphrase: ", pass, sizeof(pass), global_rpp_flags))
                err(1, "Error getting passphrase");

	/* Derive the key, then zero the passphrase */
	derive_key(hdr, pass, symkey);
	explicit_bzero(pass, sizeof(pass));

	/* Unlock passphrase buf */
	if (munlock(pass, sizeof(pass)) != 0)
		errx(1, "Error unlocking passphrase buf");

	/* Decrypt */
        if (crypto_secretbox_open(ptext_buf, ctext_buf, hdr->padded_len,
            hdr->nonce, symkey) != 0)
                errx(1, "Error decrypting data");

	/* Zero the key */
	explicit_bzero(symkey, sizeof(symkey));

	/* Unlock symmetric key buf */
	if (munlock(symkey, sizeof(symkey)) !=0 )
		errx(1, "Error unlocking symmetric key buf");
}

void
derive_key(struct hdr *hdr, char *pass, unsigned char *symkey)
{
	/* Derive symmetric key from passphrase. Note that the salt in
	 * this case is just the nonce we generated earlier. It is long,
	 * random, and unique per message, so this is safe to use here
	 */
	if (argon2id_hash_raw(hdr->rounds, hdr->mem, hdr->threads, pass, strlen(pass), hdr->nonce,
                sizeof(hdr->nonce), symkey, SYMKEYBYTES) != 0)
		errx(1, "Argon2 could not derive key");
}
