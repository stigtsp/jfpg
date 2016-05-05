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

#define	FILENAME_SIZE	255
#define	EXT	".xsalsa20"
#define	SIGNEXT	".signed"
#define	PUB	"-pubkey.curve25519"
#define	SEC	"-secretkey.curve25519"
#define	PUBSIGN	"-signing-pubkey.ed25519"
#define	SECSIGN	"-signing-secretkey.ed25519"

#define	B64NAMESIZE	192
#define	PUBKEYBYTES	crypto_box_PUBLICKEYBYTES
#define	SECKEYBYTES	crypto_box_SECRETKEYBYTES
#define	NONCEBYTES	crypto_box_NONCEBYTES
#define	ZEROBYTES	crypto_box_ZEROBYTES
#define	SIGNSKEYBYTES	crypto_sign_SECRETKEYBYTES
#define	SIGNPKEYBYTES	crypto_sign_PUBLICKEYBYTES

void usage(void);
void safer_free(void *, size_t);
void write_file(FILE *, void *, size_t, char *); 
int jf_encrypt(FILE *, FILE *, FILE *, char *);
int jf_decrypt(FILE *, FILE *, FILE *, char *);
int jf_newkey(char *);
int jf_sign(FILE *, FILE *, char *);
int jf_verify(FILE *, FILE *, char *);
unsigned long long get_size(FILE *);
