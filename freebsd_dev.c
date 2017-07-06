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
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <strings.h>
#include <err.h>
#include <errno.h>
#include <camlib.h>
#include <cam/scsi/scsi_message.h>

#include "libsmart.h"
#include "libsmart_priv.h"

struct fbsd_smart {
	smart_t	common;
	struct cam_device *camdev;
};

static smart_protocol_e __device_get_proto(struct fbsd_smart *);
static int32_t __device_get_info(struct fbsd_smart *);

smart_h
device_open(smart_protocol_e protocol, char *devname)
{
	struct fbsd_smart *h = NULL;

	h = malloc(sizeof(struct fbsd_smart));
	if (h != NULL) {
		bzero(h, sizeof(struct fbsd_smart));

		h->common.protocol = SMART_PROTO_MAX;
		h->camdev = cam_open_device(devname, O_RDWR);
		if (h->camdev == NULL) {
			printf("%s: error opening %s - %s\n",
					__func__, devname,
					cam_errbuf);
			free(h);
			h = NULL;
		} else {
			smart_protocol_e proto = __device_get_proto(h);

			if ((protocol == SMART_PROTO_AUTO) ||
					(protocol == proto)) {
				h->common.protocol = proto;
			} else {
				printf("%s: protocol mismatch %d vs %d\n",
						__func__, protocol, proto);
			}

			__device_get_info(h);
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

	return 0;
}

static int32_t
__device_read_nvme(smart_h h, union ccb *ccb, void *buf, size_t bsize)
{
	struct ccb_nvmeio *nvmeio = &ccb->nvmeio;
	uint32_t numd = 0;

/* TODO Don't enable until CAM support exists */
#if 0
	/* Subtract 1 because NUMD is a zero based value */
	numd = (sizeof(struct nvme_health_information_page) / sizeof(uint32_t))
		- 1;

	nvmeio->cmd.opc = NVME_OPC_GET_LOG_PAGE;
	nvmeio->cmd.nsid = NVME_GLOBAL_NAMESPACE_TAG;
	nvmeio->cmd.cdw10 = NVME_LOG_HEALTH_INFORMATION | (numd << 16);

	cam_fill_nvmeadmin(&ccb->nvmeio,
			/* retries */1,
			/* cbfcnp */NULL,
			/* flags */CAM_DIR_IN,
			/* data_ptr */buf,
			/* dxfer_len */bsize,
			/* timeout */5000);
#endif
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

	switch (fsmart->common.protocol) {
	case SMART_PROTO_ATA:
		__device_read_ata(h, ccb, buf, bsize);
		break;
	case SMART_PROTO_NVME:
		__device_read_nvme(h, ccb, buf, bsize);
		break;
	default:
		warn("unsupported protocol %d", fsmart->common.protocol);
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

/**
 * Retrieve the device protocol type via the transport settings
 *
 * @return protocol type or SMART_PROTO_MAX on error
 */
static smart_protocol_e
__device_get_proto(struct fbsd_smart *fsmart)
{
	smart_protocol_e proto = SMART_PROTO_MAX;
	union ccb *ccb;

	if (!fsmart || !fsmart->camdev) {
		warn("Bad handle %p", fsmart);
		return proto;
	}

	ccb = cam_getccb(fsmart->camdev);
	if (ccb != NULL) {
		CCB_CLEAR_ALL_EXCEPT_HDR(&ccb->cts);

		ccb->ccb_h.func_code = XPT_GET_TRAN_SETTINGS;
		ccb->cts.type = CTS_TYPE_CURRENT_SETTINGS;

		if (cam_send_ccb(fsmart->camdev, ccb) >= 0) {
			if ((ccb->ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_CMP) {
				struct ccb_trans_settings *cts = &ccb->cts;

				switch (cts->protocol) {
				case PROTO_ATA:
					proto = SMART_PROTO_ATA;
					break;
				case PROTO_SCSI:
					proto = SMART_PROTO_SCSI;
					break;
				case PROTO_NVME:
					proto = SMART_PROTO_NVME;
					break;
				default:
					printf("%s: unknown protocol %d\n",
							__func__,
							cts->protocol);
				}
			}
		}

		cam_freeccb(ccb);
	}

	return proto;
}

static int32_t
__device_info_ata(struct fbsd_smart *fsmart, struct ccb_getdev *cgd)
{
	smart_info_t *sinfo = NULL;

	if (!fsmart || !cgd) {
		return -1;
	}

	sinfo = &fsmart->common.info;
	
	sinfo->supported = cgd->ident_data.support.command1 &
		ATA_SUPPORT_SMART;

	cam_strvis((uint8_t *)sinfo->device, cgd->ident_data.model,
			sizeof(cgd->ident_data.model),
			sizeof(sinfo->device));
	cam_strvis((uint8_t *)sinfo->rev, cgd->ident_data.revision,
			sizeof(cgd->ident_data.revision),
			sizeof(sinfo->rev));
	cam_strvis((uint8_t *)sinfo->serial, cgd->ident_data.serial,
			sizeof(cgd->ident_data.serial),
			sizeof(sinfo->serial));

	return 0;
}

static int32_t
__device_info_scsi(struct fbsd_smart *fsmart, struct ccb_getdev *cgd)
{
	smart_info_t *sinfo = NULL;
	union ccb *ccb = NULL;
	struct scsi_vpd_unit_serial_number *snum = NULL;

	if (!fsmart || !cgd) {
		return -1;
	}

	sinfo = &fsmart->common.info;

	cam_strvis((uint8_t *)sinfo->vendor, (uint8_t *)cgd->inq_data.vendor,
			sizeof(cgd->inq_data.vendor),
			sizeof(sinfo->vendor));
	cam_strvis((uint8_t *)sinfo->device, (uint8_t *)cgd->inq_data.product,
			sizeof(cgd->inq_data.product),
			sizeof(sinfo->device));
	cam_strvis((uint8_t *)sinfo->rev, (uint8_t *)cgd->inq_data.revision,
			sizeof(cgd->inq_data.revision),
			sizeof(sinfo->rev));

	ccb = cam_getccb(fsmart->camdev);
	snum = malloc(sizeof(struct scsi_vpd_unit_serial_number));
	if (!ccb || !snum) {
		warn("Allocation failure ccb=%p snum=%p", ccb, snum);
		goto __device_info_scsi_out;
	}

	CCB_CLEAR_ALL_EXCEPT_HDR(&ccb->csio);

	scsi_inquiry(&ccb->csio,
			3, // retries
			NULL, // callback function
			MSG_SIMPLE_Q_TAG, // tag action
			(uint8_t *)snum,
			sizeof(struct scsi_vpd_unit_serial_number),
			1, // EVPD
			SVPD_UNIT_SERIAL_NUMBER, // page code
			SSD_FULL_SIZE, // sense length
			5000); // timeout

	ccb->ccb_h.flags |= CAM_DEV_QFRZDIS;

	if ((cam_send_ccb(fsmart->camdev, ccb) >= 0) &&
			((ccb->ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_CMP)) {
		cam_strvis((uint8_t *)sinfo->serial, snum->serial_num,
				snum->length,
				sizeof(sinfo->serial));
		sinfo->serial[sizeof(sinfo->serial) -1] = '\0';
	}

__device_info_scsi_out:
	if (snum)
		free(snum);
	if (ccb)
		cam_freeccb(ccb);

	return 0;
}

static int32_t
__device_info_nvme(struct fbsd_smart *fsmart, struct ccb_getdev *cgd)
{
	union ccb *ccb;
	smart_info_t *sinfo = NULL;
	struct nvme_controller_data cd;

	if (!fsmart || !cgd) {
		return -1;
	}

	sinfo = &fsmart->common.info;
	
	sinfo->supported = true;

	ccb = cam_getccb(fsmart->camdev);
	if (ccb != NULL) {
		struct ccb_dev_advinfo *cdai = &ccb->cdai;

		CCB_CLEAR_ALL_EXCEPT_HDR(cdai);

		cdai->ccb_h.func_code = XPT_DEV_ADVINFO;
		cdai->ccb_h.flags = CAM_DIR_IN;
		cdai->flags = CDAI_FLAG_NONE;
#ifdef CDAI_TYPE_NVME_CNTRL
		cdai->buftype = CDAI_TYPE_NVME_CNTRL;
#else
		cdai->buftype = 6;
#endif
		cdai->bufsiz = sizeof(struct nvme_controller_data);
		cdai->buf = (uint8_t *)&cd;

		if (cam_send_ccb(fsmart->camdev, ccb) >= 0) {
			if ((ccb->ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_CMP) {
				cam_strvis((uint8_t *)sinfo->device, cd.mn,
						sizeof(cd.mn),
						sizeof(sinfo->device));
				cam_strvis((uint8_t *)sinfo->rev, cd.fr,
						sizeof(cd.fr),
						sizeof(sinfo->rev));
				cam_strvis((uint8_t *)sinfo->serial, cd.sn,
						sizeof(cd.sn),
						sizeof(sinfo->serial));
			}
		}

		cam_freeccb(ccb);
	}

	return 0;
}

/**
 * Retrieve the device information and use to populate the info structure
 */
static int32_t
__device_get_info(struct fbsd_smart *fsmart)
{
	union ccb *ccb;
	int32_t rc = -1;

	if (!fsmart || !fsmart->camdev) {
		warn("Bad handle %p", fsmart);
		return -1;
	}

	ccb = cam_getccb(fsmart->camdev);
	if (ccb != NULL) {
		struct ccb_getdev *cgd = &ccb->cgd;

		CCB_CLEAR_ALL_EXCEPT_HDR(cgd);

		/*
		 * XXX although convenient, GDEV_TYPE won't work for NVMe b/c
		 * of the pointer silliness. What we get from GDEV_TYPE is:
		 *  - device (ata/model, scsi/product)
		 *  - revision (ata, scsi)
		 *  - serial (ata)
		 *  - vendor (scsi)
		 *  - supported (ata)
		 *
		 *  Serial # for all proto via ccb_dev_advinfo (buftype CDAI_TYPE_SERIAL_NUM)
		 */
		ccb->ccb_h.func_code = XPT_GDEV_TYPE;

		if (cam_send_ccb(fsmart->camdev, ccb) >= 0) {
			if ((ccb->ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_CMP) {
				switch (cgd->protocol) {
				case PROTO_ATA:
					rc = __device_info_ata(fsmart, cgd);
					break;
				case PROTO_SCSI:
					rc = __device_info_scsi(fsmart, cgd);
					break;
				case PROTO_NVME:
					rc = __device_info_nvme(fsmart, cgd);
					break;
				default:
					printf("%s: unsupported protocol %d\n",
							__func__, cgd->protocol);
				}
			}
		}

		cam_freeccb(ccb);
	}

	return rc;
}
