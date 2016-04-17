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
#include "bsdcompat/compat.h"

int
main(int argc, char **argv)
{
	int ch, flag = 0;
	FILE *infile = NULL;
	FILE *key = NULL;
	FILE *skey = NULL;
	FILE *sign_key = NULL;
	char filename[FILENAME_SIZE];
	char id[128];
	
	memset(id, 0, sizeof(id));
	
	if (argc < 2)
		usage();

	while ((ch = getopt(argc, argv, "vsedn:k:x:s:p:f:")) != -1) {
		switch (ch) {
		case 'n':
		    if (argc != 3)
			usage();
		    if (strlcpy(id, optarg, sizeof(id)) >= sizeof(id))
			errx(1, "name too long");
		    flag = 1;
		    break;
		case 'e':
		    if (argc != 8)
			usage();
		    flag = 2;
		    break;
		case 'd':
		    if (argc != 8)
			usage();
		    flag = 3;
		    break;
	 	case 's':
		    if (argc != 6)
			usage();
		    flag = 4;
		    break;
		case 'v':
		    if (argc != 6)
			usage();
		    flag = 5;
		    break;
		case 'k':
		    if ((skey = fopen(optarg, "rb")) == NULL)
			err(1, "Couldn't find secret key");
		    break;
		case 'p':
		    if ((key = fopen(optarg, "r")) == NULL)
			err(1, "Couldn't find public key");
		    break;
		case 'x':
		    if ((sign_key = fopen(optarg, "r")) == NULL)
			err(1, "error opening signing/verifying key");
		    break;
		case 'f':
		    if ((infile = fopen(optarg, "r")) == NULL)
			err(1, "Couldn't find file");
		    if (strlcpy(filename, optarg, FILENAME_SIZE) >= FILENAME_SIZE)
			errx(1, "Filename too long");
		    break;
		default:
		    usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 1)
		usage();

	if (flag == 1) {
		if (jf_newkey(id) != 0)
		    errx(1, "error creating keypair");
	} else if (flag == 2) {
		if (jf_encrypt(infile, key, skey, filename) != 0)
		    errx(1, "error encrypting");
		printf("encryption successful\n");
	} else if (flag == 3) {
		if (jf_decrypt(infile, key, skey, filename) != 0)
	  	    errx(1, "error decrypting");
		printf("decryption successful\n");
	} else if (flag == 4) {
		if (jf_sign(infile, sign_key, filename) != 0)
		    errx(1, "error signing");
		printf("signed %s\n", filename);
	} else if (flag == 5) {
		if (jf_verify(infile, sign_key, filename) != 0)
		    errx(1, "error verifying signature");
		printf("good signature\n");
	}
	return (0);
}

void
usage(void)
{
	errx(1, "\nusage:\n\tjfpg -n new-key-id\n\tjfpg -s -f file -x signing-secretkey \
	    \n\tjfpg -v -f file -x signing-publickey \
	    \n\tjfpg [-e | -d] -f file -p publickey -s secretkey");
}
