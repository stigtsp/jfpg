#include <string.h>

#include "base64.h"

size_t
encode_len(size_t len)
{
        len = (len + 2) / 3 * 4 + 1;
	return len;
}

size_t
decode_len(unsigned char *buf)
{
        size_t len = strlen(buf);
        int padlen = 0;
        if (buf[len - 2] == '=')
                padlen = 2;
        else
                padlen = 1;
        return ((len * 3) / 4) - padlen;
}
