/*
 * Copyright (c) 2016-2021 Chuck Tuffli <chuck@tuffli.net>
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

#define PAGE_ID_SCSI_SUPPORTED_PAGES	0x00
#define PAGE_ID_SCSI_WRITE_ERR		0x02		/* Write Error counter */
#define PAGE_ID_SCSI_READ_ERR		0x03		/* Read Error counter */
#define PAGE_ID_SCSI_VERIFY_ERR		0x05		/* Verify Error counter */
#define PAGE_ID_SCSI_NON_MEDIUM_ERR	0x06		/* Non-Medium Error */
#define PAGE_ID_SCSI_LAST_N_ERR		0x07		/* Last n Error events */
#define PAGE_ID_SCSI_TEMPERATURE	0x0d		/* Temperature */
#define PAGE_ID_SCSI_START_STOP_CYCLE	0x0e		/* Start-Stop Cycle counter */
#define PAGE_ID_SCSI_INFO_EXCEPTION	0x2f		/* Informational Exceptions */

extern bool do_debug;

#define dprintf(f, ...)	if (do_debug) printf("dbg: " f, ## __VA_ARGS__)

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

char * __smart_ata_desc(uint32_t page, uint32_t id);
char * __smart_scsi_err_desc(uint32_t id);

#endif
