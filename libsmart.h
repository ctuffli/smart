/*
 * Copyright (c) 2016 Chuck Tuffli <chuck@tuffli.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
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
	void *b;
	size_t bsize;
	uint32_t vcount;
} smart_buf_t;

smart_h smart_open(smart_protocol_e p, char *devname);
void smart_close(smart_h);
smart_buf_t *smart_read(smart_h);
void smart_free(smart_buf_t *);
void smart_print(smart_h, smart_buf_t *, int32_t, uint32_t);

#endif
