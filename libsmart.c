#include <stdio.h>

#include "libsmart.h"

smart_h
smart_open(smart_protocol_e protocol, char *devname)
{
	printf("opening %s\n", devname);
	return NULL;
}

smart_value_t *
smart_val_alloc(smart_h h, uint32_t id)
{
	return NULL;
}

void
smart_val_free(smart_h h, smart_value_t *v)
{
}

