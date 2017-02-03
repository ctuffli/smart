/*
 * Copyright (c) 2016-2017 Chuck Tuffli <chuck@tuffli.net>
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
/*
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>

#include "libsmart.h"

static struct option opts[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "threshold", no_argument, NULL, 't' },
	{ "hex", no_argument, NULL, 'x' },
	{ "attribute", required_argument, NULL, 'a' },
	{ "info", no_argument, NULL, 'i' },
	{ NULL, 0, NULL, 0 }
};

void
usage(const char *name)
{
	printf("Usage: %s [-htxi] [-a <attribute id>]\n", name);
	printf("\t-h, --help\n");
	printf("\t-t, --threshold : also print out the threshold values\n");
	printf("\t-x, --hex : print the values out in hexadecimal\n");
	printf("\t-a, --attribute : print a specific attribute\n");
	printf("\t-i, --info : print general device information\n");
}

int
main(int argc, char *argv[])
{
	smart_h h;
	smart_map_t *sm = NULL;
	int ch;
	bool do_thresh = false, do_hex = false, do_info = false;
	int32_t  attr = -1;
	int rc = EXIT_SUCCESS;

	while ((ch = getopt_long(argc, argv, "htxa:i", opts, NULL)) != -1) {
		switch (ch) {
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;
			break;
		case 't':
			do_thresh = true;
			break;
		case 'x':
			do_hex = true;
			break;
		case 'a':
			// TODO use realloc() to create an array of attr to pass to smart_read() ?
			attr = atoi(optarg);
			break;
		case 'i':
			do_info = true;
			break;
		default:
			printf("unknown option %c\n", ch);
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	argc -= optind;
	argv += optind;

	h = smart_open(SMART_PROTO_AUTO, argv[0]);

	if (h == NULL) {
		printf("device open failed %s\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (do_info) {
		smart_print_device_info(h);
	}

	if (smart_supported(h)) {
		sm = smart_read(h);

		if (sm) {
			uint32_t flags = 0;

			if (do_hex)
				flags |= 0x1;
			if (do_thresh)
				flags |= 0x2;

			smart_print(h, sm, attr, flags);

			smart_free(sm);
		}
	} else {
		rc = EXIT_FAILURE;
	}

	smart_close(h);

	return rc;
}
