#include <stdio.h>
#include <stdlib.h>

#include "libsmart.h"

int
main(int argc, char *argv[])
{
	smart_h h;

	h = smart_open(SMART_PROTO_ATA, argv[1]);

	return EXIT_SUCCESS;
}
