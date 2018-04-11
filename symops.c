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
#include <stdbool.h>

#include "symops.h"
#include "compat.h"
#include "readpassphrase.h"
#include "argon2.h"
#include "tweetnacl.h"

#define SYMKEYBYTES     crypto_secretbox_KEYBYTES

extern int global_rpp_flags;

static void derive_key(struct hdr *, char *, unsigned char *);
static bool str_iseq(const char *, const char *);



/* str_iseq function written by John Schember, used under MIT License */
bool
str_iseq(const char *s1, const char *s2)
{
	int    m = 0;
	size_t i = 0;
	size_t j = 0;
	size_t k = 0;
			 
	if (s1 == NULL || s2 == NULL)
		return false;
			     
	while (1) {
		m |= s1[i]^s2[j];
						 
		if (s1[i] == '\0')
		    break;
		i++;
								 
		if (s2[j] != '\0')
		    j++;
		if (s2[j] == '\0')
		    k++;
	}
			 
	return m == 0;
}
	
void
symcrypt(unsigned char *ctext_buf, unsigned char *pad_ptext_buf, struct hdr *hdr)
{
	char pass[512] = {0};
	char pass2[512] = {0};
	unsigned char symkey[SYMKEYBYTES] = {0};

	if (mlock(pass, sizeof(pass)) !=0)
		errx(1, "Error locking passphrase buf");
	if (mlock(pass2, sizeof(pass2)) !=0)
		errx(1, "Error locking passphrase 2 buf");
	if (mlock(symkey, sizeof(symkey)) !=0)
		errx(1, "Error locking symmetric key buf");

	/* Read in and confirm passphrase */
	if (!readpassphrase("Enter new passphrase: ", pass, sizeof(pass), global_rpp_flags))
		err(1, "Error getting passphrase");

	/* Only confirm passphrase if we're requiring a tty. This way we
	 * skip this when using stdin to make it easier to pipe in a passphrase
	 */
	if (global_rpp_flags == RPP_REQUIRE_TTY) {
		if (!readpassphrase("Confirm new passphrase: ", pass2, sizeof(pass2), global_rpp_flags)) {
                    explicit_bzero(pass, sizeof(pass));
		    explicit_bzero(pass2, sizeof(pass2));
		    err(1, "Error confirming passphrase");
		}
        	if (str_iseq(pass, pass2) == 0) {
		    explicit_bzero(pass, sizeof(pass));
	            explicit_bzero(pass2, sizeof(pass2));	
                    errx(1, "Passphrases do not match");
		}
        }

	/* Zero the extra passphrase buffer, derive the key, then zero the
	 * other passphrase buffer too
	 */
	explicit_bzero(pass2, sizeof(pass2));
	if (munlock(pass2, sizeof(pass2)) !=0)
		errx(1, "Error unlocking passphrase 2 buf");

	derive_key(hdr, pass, symkey);

	explicit_bzero(pass, sizeof(pass));
	if (munlock(pass, sizeof(pass)) !=0)
		errx(1, "Error unlocking passphrase buf");

	/* Encrypt */
	if (crypto_secretbox(ctext_buf, pad_ptext_buf, hdr->padded_len,
	    hdr->nonce, symkey) != 0)
		errx(1, "Error encrypting message");

	/* Zero the key */
	explicit_bzero(symkey, sizeof(symkey));
	if (munlock(symkey, sizeof(symkey)) !=0)
		errx(1, "Error unlocking symmetric key");
}

void
symdecrypt(unsigned char *ptext_buf, unsigned char *ctext_buf, struct hdr *hdr)
{
        char pass[512] = {0};
        unsigned char symkey[SYMKEYBYTES] = {0};

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
