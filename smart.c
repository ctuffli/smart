#include <stdio.h>
#include <stdlib.h>

#include "libsmart.h"

int
main(int argc, char *argv[])
{
	smart_h h;
	smart_buf_t *sb = NULL;

	h = smart_open(SMART_PROTO_ATA, argv[1]);

	if (h == NULL) {
		printf("device open failed %s\n", argv[1]);
		return EXIT_FAILURE;
	}

	sb = smart_read(h);
	if (sb) {
		smart_free(sb);
	}

	smart_close(h);

	return EXIT_SUCCESS;
}
