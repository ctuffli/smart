/*
 * Copyright (c) 2016-2018 Chuck Tuffli <chuck@tuffli.net>
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
#ifndef _LIBSMART_PRIV_H
#define _LIBSMART_PRIV_H

#define PAGE_ID_ATA_SMART_READ_DATA	0xd0		/* SMART Read Data */
#define PAGE_ID_ATA_SMART_RET_STATUS	0xda		/* SMART Return Status */

extern bool do_debug;

#define dprintf(f, ...)	if (do_debug) printf("dbg: " f, __VA_ARGS__)

typedef struct smart_info_s {
	uint32_t supported:1,
		 tunneled:1,
		 :30;
	char vendor[16], device[48], rev[16], serial[32];
} smart_info_t;

typedef struct smart_page_list_s {
	uint32_t	pg_count;
	struct {
		uint32_t id;
		size_t	bytes;
	} pages[];
} smart_page_list_t;

typedef struct smart_s {
	smart_protocol_e protocol;
	smart_info_t info;
	smart_page_list_t *pg_list;
	/* Device / OS specific follows this structure */
} smart_t;

#endif
