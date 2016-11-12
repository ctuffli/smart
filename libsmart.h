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
	uint32_t id;	/** SMART attribute ID / offset */
	size_t size;	/** Number of bytes */
	char *name;
	uint8_t *raw;
} smart_value_t;

typedef struct {
	smart_protocol_e protocol;
	void *b;
	size_t bsize;
	uint32_t vcount;
	smart_value_t val[];
} smart_buf_t;

smart_h smart_open(smart_protocol_e p, char *devname);
void smart_close(smart_h);
smart_buf_t *smart_read(smart_h);
void smart_free(smart_buf_t *);

#endif
