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
#include <unistd.h>
#include <string.h>

#include "jfpg.h"
#include "defines.h"
#include "compat.h"
#include "readpassphrase.h"

/* Global variable to control readpassphrase flags.
 * It is only possible to modify this once, through a 
 * command line flag.
 */
int global_rpp_flags = RPP_REQUIRE_TTY;

static void usage(void);

int
main(int argc, char **argv)
{
	int ch, flag = 0;
	long long rounds = ARGON2_T;
	long long mem = ARGON2_MEM * 1024;
	FILE *infile = NULL;
	FILE *pkey = NULL;
	FILE *skey = NULL;
	char filename[FILENAME_SIZE];
	char id[IDSIZE];
	const char *errstr;

	memset(id, 0, sizeof(id));
	
	if (argc < 2)
		usage();

	while ((ch = getopt(argc, argv, "vscedSn:k:s:p:f:r:m:")) != -1) {
		switch (ch) {
		case 'n':
		    if (jf_strlcpy(id, optarg, sizeof(id)) >= sizeof(id))
			errx(1, "Name too long");
		    flag = 1;
		    break;
		case 'e':
		    flag = 2;
		    break;
		case 'c':
		    flag = 3;
		    break;
		case 'd':
		    flag = 4;
		    break;
	 	case 's':
		    flag = 5;
		    break;
		case 'v':
		    flag = 6;
		    break;
		case 'S':
		    global_rpp_flags = RPP_STDIN;
		    break;
		case 'k':
		    if ((skey = fopen(optarg, "r")) == NULL)
			err(1, "Couldn't find secret key");
		    break;
		case 'p':
		    if ((pkey = fopen(optarg, "r")) == NULL)
			err(1, "Couldn't find public key");
		    break;
		case 'f':
		    if ((infile = fopen(optarg, "r")) == NULL)
			err(1, "Couldn't find file");
		    if (jf_strlcpy(filename, optarg, FILENAME_SIZE) >= FILENAME_SIZE)
			errx(1, "Filename too long");
		    break;
		case 'r':
		    rounds = strtonum(optarg, MIN_ROUNDS, MAX_ROUNDS, &errstr);
		    if (errstr != NULL)
			errx(1, "Error getting rounds: %s", errstr);
		    break;
		case 'm':
		    mem = strtonum(optarg, MIN_MEM, MAX_MEM, &errstr);
		    if (errstr != NULL)
			errx(1, "Error setting KDF memory: %s", errstr);
		    mem = (mem * 1024);
		    break;
		default:
		    usage();
		    break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	if (flag == 0)
		usage();

	if (flag == 1) {
	
		/* Generating new key pairs */	
		jf_newkey(id, rounds, mem);
	
	} else if (flag == 2) {

		/* Asymmetric encryption */
		if (infile == NULL)
		    errx(1, "Must provide a file for encryption");
		if (pkey == NULL)
		    errx(1, "Must provide recipient's public key");
		if (skey == NULL)
		    errx(1, "Must provide sender's secret key");
		jf_encrypt(infile, pkey, skey, filename, 1, 1, 1);

	} else if (flag == 3) {

		/* Symmetric encryption */
		if (infile == NULL)
		    errx(1, "Must provide a file for encryption");
		jf_encrypt(infile, NULL, NULL, filename, 2, rounds, mem);

	} else if (flag == 4) {
	
		/* Decryption */
		if (infile == NULL)
		    errx(1, "Must provide a file for decryption");
		jf_decrypt(infile, pkey, skey, filename);

	} else if (flag == 5) {

		/* Signing */
		if (infile == NULL)
		    errx(1, "Must provide a file for signing");	
		if (skey == NULL)
		    errx(1, "Must provide signer's secret key");
		jf_sign(infile, skey, filename);

	} else if (flag == 6) {

		/* Verifying signed file */
		if (infile == NULL)
		    errx(1, "Must provide a file for sig verification");
		if (pkey == NULL)
		    errx(1, "Must provide signer's public key");
		jf_verify(infile, pkey, filename);

	}

	return (0);
}

void
usage(void)
{
	errx(1, "\nusage:\n\tjfpg -c [-S] [-r rounds] [-m memory] -f file\
	    \n\tjfpg -e [-S] -p recip-pubkey -k sender-seckey -f file \
	    \n\tjfpg -d [-S] [-p sender-pubkey -k recip-seckey] -f file \
	    \n\tjfpg -s [-S] -k signer-signing-seckey -f file\
	    \n\tjfpg -v -p signer-signing-pubkey -f file\
	    \n\tjfpg -n [-S] [-r rounds] [-m memory] key-id");
}
