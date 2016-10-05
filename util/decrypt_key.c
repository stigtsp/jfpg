#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "../symops.h"
#include "utils.h"

void
decrypt_key(unsigned char *key_plain, FILE *key_fd)
{
	unsigned char *key_crypt = NULL;
	struct hdr *hdr = NULL;
	
	hdr = malloc(sizeof(struct hdr));
	if (hdr == NULL)
                err(1, "error allocating hdr");
        if (fread(hdr, 1, sizeof(struct hdr), key_fd) != sizeof(struct hdr))
                errx(1, "error reading in header");
	if ((key_crypt = malloc(hdr->padded_len)) == NULL)
                err(1, "error allocating buf for encrypted key");
        if (fread(key_crypt, 1, hdr->padded_len, key_fd) != hdr->padded_len)
                errx(1, "error reading in ciphertext");
	
	symdecrypt(key_plain, key_crypt, hdr);
	safer_free(key_crypt, sizeof(key_crypt));
	free(hdr);
}
