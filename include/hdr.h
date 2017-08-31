#ifndef _HDR_H
#define _HDR_H

#include <inttypes.h>

#include "tweetnacl.h"

#pragma pack (1)
struct hdr {
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        uint64_t padded_len;
        uint32_t rounds;
        uint32_t mem;
        uint32_t threads;
        int alg;
};
#endif
