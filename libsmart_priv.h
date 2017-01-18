#ifndef _LIBSMART_PRIV_H
#define _LIBSMART_PRIV_H

typedef struct smart_s {
	smart_protocol_e protocol;
	/* Device / OS specific follows this structure */
} smart_t;

#endif
