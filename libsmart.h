#ifndef _LIBSMART_H
#define _LIBSMART_H

#include <inttypes.h>

typedef void * smart_h;

typedef enum {
	SMART_PROTO_ATA,
	SMART_PROTO_SCSI,
	SMART_PROTO_NVME,
	SMART_PROTO_MAX
} smart_protocol_e;

typedef struct {
	smart_protocol_e protocol;
	uint32_t id;	/** SMART attribute ID / offset */
	size_t size;	/** Number of bytes */
	char *name;
	uint8_t raw[];
} smart_value_t;

smart_h smart_open(smart_protocol_e p, char *devname);
smart_value_t *smart_val_alloc(smart_h h, uint32_t id);
void smart_val_free(smart_h h, smart_value_t *v);
int32_t smart_val_get(smart_h h, smart_value_t *v);

#endif
