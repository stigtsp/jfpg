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

#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "base64.h"
#include "compat.h"
#include "defines.h"
#include "tweetnacl.h"
#include "symops.h"

void
decrypt_key(unsigned char *key_plain, FILE *key_fd)
{
        unsigned char *key_crypt = NULL;
        struct hdr *hdr = NULL;

        hdr = malloc(sizeof(struct hdr));
        if (hdr == NULL)
                err(1, "error allocating hdr");

        read_hdr(hdr, key_fd);
        if ((key_crypt = malloc(hdr->padded_len)) == NULL)
                err(1, "error allocating buf for encrypted key");
        if (fread(key_crypt, 1, hdr->padded_len, key_fd) != hdr->padded_len)
                errx(1, "error reading in ciphertext");

        symdecrypt(key_plain, key_crypt, hdr);
        explicit_bzero(key_crypt, hdr->padded_len);
	free(key_crypt);
        free(hdr);
}


void
get_keys(unsigned char *pk, unsigned char *sk, FILE *fd_pk, FILE *fd_sk)
{
        int b64len = encode_len(PUBKEYBYTES);
        char b64_pk[b64len];

        if (fread(b64_pk, 1, b64len, fd_pk) != b64len - 1)
                errx(1, "could not read in base64 pubkey");
        decrypt_key(sk, fd_sk);
        fclose(fd_pk);
        fclose(fd_sk);

        b64_pton(b64_pk, pk, PUBKEYBYTES);
}

unsigned long long
get_size(FILE *infile)
{
        unsigned long long infile_size = 0;

        fseek(infile, 0, SEEK_END);
        infile_size = ftell(infile);
        rewind(infile);
        return (infile_size);
}

void
read_infile(FILE *infile, unsigned char *buf, unsigned long long size)
{
        if (infile == NULL)
                errx(1, "error reading in infile");
        if (fread(buf, 1, size, infile) != size)
                errx(1, "error reading from buf");
        fclose(infile);
}

void
write_file(FILE *fd, void *buf, size_t bufsize, char *filename)
{
        if ((fd = fopen(filename, "w")) == NULL)
                err(1, "error creating file");
        fwrite(buf, 1, bufsize, fd);
	fclose(fd);
}

size_t
encode_len(size_t len)
{
        len = (len + 2) / 3 * 4 + 1;
        return len;
}

size_t
decode_len(char *buf)
{
        size_t len = strlen(buf);
        int padlen = 0;
        if (buf[len - 2] == '=')
                padlen = 2;
        else
                padlen = 1;
        return ((len * 3) / 4) - padlen;
}

void
read_hdr(struct hdr *hdr, FILE *infile)
{
	if (fread(hdr->nonce, 1, sizeof(hdr->nonce), infile) != sizeof(hdr->nonce))
                err(1, "error reading in nonce");
        if (fscanf(infile, " %" PRIu64 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %d ", &hdr->padded_len, &hdr->rounds,
                &hdr->mem, &hdr->threads, &hdr->alg) < 5)
		errx(1, "Error reading file header");
}

void
write_enc(FILE *outfile, struct hdr *hdr, unsigned char *ctext_buf, char *filename)
{
        outfile = fopen(filename, "w");
        fwrite(hdr->nonce, 1, sizeof(hdr->nonce), outfile);
        fprintf(outfile, " %" PRIu64 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %d ", hdr->padded_len,
                hdr->rounds, hdr->mem, hdr->threads, hdr->alg);
        fwrite(ctext_buf, 1, hdr->padded_len, outfile);
        fclose(outfile);
}
