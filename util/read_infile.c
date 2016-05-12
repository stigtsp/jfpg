#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "../jfpg.h"

void 
read_infile(FILE *infile, unsigned char *buf, unsigned long long size)
{
	if (fread(buf, 1, size, infile) != size)
		errx(1, "error reading from buf");
	fclose(infile);
}
