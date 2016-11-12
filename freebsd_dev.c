#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <strings.h>
#include <err.h>
#include <errno.h>
#include <camlib.h>

#include "libsmart.h"

struct fbsd_smart {
	struct cam_device *camdev;
	smart_protocol_e protocol;
};

smart_h
device_open(smart_protocol_e protocol, char *devname)
{
	struct fbsd_smart *h = NULL;

	h = malloc(sizeof(struct fbsd_smart));
	if (h != NULL) {
		h->protocol = protocol;
		h->camdev = cam_open_device(devname, O_RDWR);
		if (h->camdev == NULL) {
			printf("%s: error opening %s - %s\n",
					__func__, devname,
					cam_errbuf);
			free(h);
			h = NULL;
		}
	}

	return h;
}

void
device_close(smart_h h)
{
	struct fbsd_smart *fsmart = h;

	if (fsmart != NULL) {
		if (fsmart->camdev !=NULL) {
			cam_close_device(fsmart->camdev);
		}

		free(fsmart);
	}
}

static const uint8_t smart_fis[] = {
	0xb0, 0xd0, 0x00, 0x4f, 0xc2, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static int32_t
__device_read_ata(smart_h h, union ccb *ccb, void *buf, size_t bsize)
{

	bcopy(smart_fis, &ccb->ataio.cmd.command, sizeof(smart_fis));

	cam_fill_ataio(&ccb->ataio,
			/* retries */1,
			/* cbfcnp */NULL,
			/* flags */CAM_DIR_IN,
			/* tag_action */0,
			/* data_ptr */buf,
			/* dxfer_len */bsize,
			/* timeout */5000);
	ccb->ataio.cmd.flags |= CAM_ATAIO_NEEDRESULT;
	ccb->ataio.cmd.control = 0;
/*
	printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			ccb->ataio.res.status,
			ccb->ataio.res.error,
			ccb->ataio.res.lba_low,
			ccb->ataio.res.lba_mid,
			ccb->ataio.res.lba_high,
			ccb->ataio.res.device,
			ccb->ataio.res.lba_low_exp,
			ccb->ataio.res.lba_mid_exp,
			ccb->ataio.res.lba_high_exp,
			ccb->ataio.res.sector_count,
			ccb->ataio.res.sector_count_exp);
*/
	return 0;
}

int32_t
device_read(smart_h h, void *buf, size_t bsize)
{
	struct fbsd_smart *fsmart = h;
	union ccb *ccb = NULL;
	int retval;

	if (fsmart == NULL)
		return EINVAL;

	ccb = cam_getccb(fsmart->camdev);
	if (ccb == NULL)
		return ENOMEM;

	CCB_CLEAR_ALL_EXCEPT_HDR(ccb);

	switch (fsmart->protocol) {
	case SMART_PROTO_ATA:
		__device_read_ata(h, ccb, buf, bsize);
		break;
	default:
		warn("unsupported protocol %d", fsmart->protocol);
		cam_freeccb(ccb);
		return -1;
	}

	if (((retval = cam_send_ccb(fsmart->camdev, ccb)) < 0)
			|| ((ccb->ccb_h.status & CAM_STATUS_MASK) != CAM_REQ_CMP)) {
		if (retval < 0)
			warn("error sending command");

		cam_error_print(fsmart->camdev, ccb, CAM_ESF_ALL,
				CAM_EPF_ALL, stderr);
	}

	cam_freeccb(ccb);

	return 0;
}
