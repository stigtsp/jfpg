#ifndef _HDR_H
#define _HDR_H

#include "tweetnacl.h"

#pragma pack (1)
struct hdr {
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        unsigned long long padded_len;
        long long rounds;
        long long mem;
        unsigned int p;
        int alg;
};
#endif
