/* Use arc4random on systems that have a modern implementation.
   Currently, I'm limiting this to OpenBSD. 
 */
#ifdef __OpenBSD__

#include <err.h>
#include <stdlib.h>
#include <inttypes.h>

void randombytes(unsigned char *x,unsigned long long xlen)
{
  /* We should never ask for more than SIZE_MAX bytes */
  if (xlen > SIZE_MAX)
    errx(1, "Can't provide more than SIZE_MAX random bytes");
  arc4random_buf(x, (size_t)xlen);
}
 
#else /* no arc4random(), so carefully try /dev/urandom */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* it's really stupid that there isn't a syscall for this */

static int fd = -1;

void randombytes(unsigned char *x,unsigned long long xlen)
{
  int i;

  if (fd == -1) {
    for (;;) {
      fd = open("/dev/urandom",O_RDONLY);
      if (fd != -1) break;
      sleep(1);
    }
  }

  while (xlen > 0) {
    if (xlen < 1048576) i = xlen; else i = 1048576;

    i = read(fd,x,i);
    if (i < 1) {
      sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
}

#endif
