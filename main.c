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
#include <math.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "jfpg.h"
#include "bsdcompat/compat.h"

int
main(int argc, char **argv)
{
	int ch, flag = 0;
	long long rounds = 0;
	FILE *infile = NULL;
	FILE *pkey = NULL;
	FILE *skey = NULL;
	char filename[FILENAME_SIZE];
	char id[IDSIZE];
	const char *errstr;

	memset(id, 0, sizeof(id));
	
	if (argc < 2)
		usage();

	while ((ch = getopt(argc, argv, "vscedn:k:s:p:f:r:")) != -1) {
		switch (ch) {
		case 'n':
		    if (strlcpy(id, optarg, sizeof(id)) >= sizeof(id))
			errx(1, "name too long");
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
		    if (strlcpy(filename, optarg, FILENAME_SIZE) >= FILENAME_SIZE)
			errx(1, "Filename too long");
		    break;
		case 'r':
		    rounds = strtonum(optarg, 16, 25, &errstr);
		    if (errstr != NULL)
			errx(1, "error getting rounds: %s", errstr);
		    rounds = exp2(rounds);
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

	if (flag == 1) {
		if (jf_newkey(id) != 0)
		    errx(1, "error creating keypair");
	} else if (flag == 2) {
		if (jf_encrypt(infile, pkey, skey, filename, 1, 1) != 0)
		    errx(1, "error encrypting");
		printf("encryption successful\n");
	} else if (flag == 3) {
		if (rounds == 0)
		    rounds = exp2(DEFAULT_ROUNDS);
		if (jf_encrypt(infile, NULL, NULL, filename, 2, rounds) != 0)
		    errx(1, "error encrypting");
		printf("encryption successful\n");
	} else if (flag == 4) {
		if (jf_decrypt(infile, pkey, skey, filename) != 0)
	  	    errx(1, "error decrypting");
		printf("decryption successful\n");
	} else if (flag == 5) {
		if (jf_sign(infile, skey, filename) != 0)
		    errx(1, "error signing");
		printf("signed %s\n", filename);
	} else if (flag == 6) {
		if (jf_verify(infile, pkey, filename) != 0)
		    errx(1, "error verifying signature");
		printf("good signature\n");
	}
	return (0);
}

void
usage(void)
{
	errx(1, "\nusage:\n\tjfpg -n new-key-id \
	    \n\tjfpg -s -f file -k signing-secretkey \
	    \n\tjfpg -v -f file -p signing-publickey \
	    \n\tjfpg [-e | -d] -f file -p publickey -s secretkey \
	    \n\tjfpg -c -f file -r rounds");
}
