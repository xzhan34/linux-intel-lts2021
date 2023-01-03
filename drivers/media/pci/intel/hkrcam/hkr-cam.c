// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Intel Corporation
 *
 */

#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/pci.h>
#include <linux/pci-epf.h>
#include <linux/pm_runtime.h>
#include <linux/property.h>
#include <linux/vmalloc.h>
#include <linux/timekeeping.h>

#include <media/v4l2-ctrls.h>
#include <media/v4l2-device.h>
#include <media/v4l2-event.h>
#include <media/v4l2-fwnode.h>
#include <media/v4l2-ioctl.h>
#include <media/videobuf2-dma-contig.h>

#include "hkr-pcie-hostdev.h"
#include "hkr-hid.h"
#include "hkr-cam.h"

//#define DESC_RING_ON_HOST

#define HKR_DRV_VERSION_MAJOR  (0) /* major version */
#define HKR_DRV_VERSION_MINOR  (1) /* minor version */
#define HKR_DRV_VERSION_CHG    (0) /* for several changes */

#define HKR_VENDOR_ID 0x8086
#define HKR_PRODUCT_ID 0xabcd

#define HKR_DEFAULT_WIDTH 1280
#define HKR_DEFAULT_HEIGHT 720

#define HKR_MAX_WIDTH 1920
#define HKR_MAX_HEIGHT 1080
#define HKR_DEFAULT_CODE MEDIA_BUS_FMT

#ifndef VFL_TYPE_VIDEO
#define VFL_TYPE_VIDEO 0
#endif
/*
 * We created the maximum video stream numbers we support at the
 * beginning. Then we will open the streams needed from application.
 * The number of streams needed depends on the UC application selected.
 */

#define HKR_DRIVER_NAME "hkr-cam"
#define HKR_DEVICE_NAME "Intel HKR"
#define HKR_CTRL_DRIVER_NAME "hkr_ctl"

#define HKR_INFO_LOG_EN

#define HKR_INFO(dev, ...) \
do { \
	if (enable_log) \
		dev_info(dev, ##__VA_ARGS__); \
} while (0)

static int enable_log = 0;
module_param(enable_log, int, 0644);

struct hkr_fmt {
	char  *name;
	u32   fourcc;          /* v4l2 format id */
	int   depth;
};

static struct hkr_fmt hkr_formats[] = {
	{
		.name     = "4:2:2, packed, YUYV",
		.fourcc   = V4L2_PIX_FMT_YUYV,
		.depth    = 16,
	},
	{
		.name     = "4:2:2, packed, UYVY",
		.fourcc   = V4L2_PIX_FMT_UYVY,
		.depth    = 16,
	},
	{
		.name     = "4:2:0, packed, NV12",
		.fourcc   = V4L2_PIX_FMT_NV12,
		.depth    = 12,
	},
};

static const struct v4l2_file_operations hkr_v4l2_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = video_ioctl2,
	.open = v4l2_fh_open,
	.release = vb2_fop_release,
	.poll = vb2_fop_poll,
	.mmap = vb2_fop_mmap,
};

/* TODO: we assume YUYUV8 with no pitch here */
static inline u32 hkr_bytesperline(uint32_t pixelfmt, const unsigned int width) {
	uint32_t bytesperline = 0;
	switch(pixelfmt){
	case V4L2_PIX_FMT_NV12:
		bytesperline=width * 3 / 2;
		break;
	case V4L2_PIX_FMT_YUYV:
	case V4L2_PIX_FMT_UYVY:
		bytesperline= width * 2;
		break;
	default:
		break;
	}
	return bytesperline;
}

static int hkr_alloc_ring_descs(struct hkr_device *hkr_dev)
{
#ifdef DESC_RING_ON_HOST
	size_t offset;
	size_t size;
	size_t alignment = hkr_dev->alignment;

	HKR_INFO(hkr_dev->dev, "--->alignment:%zx try:%lx", alignment,
	         PTR_ALIGN(0x44130000UL, alignment));

	size = (sizeof(struct hkr_ring_desc) * hkr_dev->stream_nums) +
	       alignment;

	hkr_dev->ring_cpu_org = dma_alloc_coherent(hkr_dev->dev,
	                        size, &hkr_dev->ring_bus_org, GFP_KERNEL);
	if (!hkr_dev->ring_cpu_org)
		return -ENOMEM;

	hkr_dev->ring_org_size = size;
	hkr_dev->each_ring_size = sizeof(struct hkr_ring_desc);

	if (!IS_ALIGNED(hkr_dev->ring_bus_org, alignment)) {
		hkr_dev->ring_bus_addr = PTR_ALIGN(hkr_dev->ring_bus_org,
		                                   alignment);

		offset = hkr_dev->ring_bus_addr - hkr_dev->ring_bus_org;
		HKR_INFO(hkr_dev->dev, "offset:%zu org-bus:%llx bus:%llx\n",
		         offset, hkr_dev->ring_bus_org, hkr_dev->ring_bus_addr);
		hkr_dev->ring_cpu_addr =
		        (struct hkr_ring_desc *) (hkr_dev->ring_cpu_org + offset);
	} else {
		hkr_dev->ring_bus_addr = hkr_dev->ring_bus_org;
		hkr_dev->ring_cpu_addr =
		        (struct hkr_ring_desc *) (hkr_dev->ring_cpu_org);
	}

	HKR_INFO(hkr_dev->dev,
	         "size:%ld bus_org:%llx bus:%llx ring_org:%p ring:%p\n",
	         sizeof(struct hkr_ring_desc) + alignment,
	         hkr_dev->ring_bus_org, hkr_dev->ring_bus_addr,
	         hkr_dev->ring_cpu_org,	hkr_dev->ring_cpu_addr);
#else
	/* As desc ring in EP bar, it is not necessary to pass bus address to
	 * EP. Becasue EP know it's BAR memory location, it doen't need to map
	 * The address. It can read the BAR location directly.
	 */
	hkr_dev->ring_cpu_org = hkr_dev->base + HKR_RING_DESC_OFF_IN_BAR;
	hkr_dev->ring_cpu_addr = hkr_dev->ring_cpu_org;
	hkr_dev->ring_bus_addr = 0;
	hkr_dev->ring_bus_org = 0;
	hkr_dev->ring_org_size =
	        (sizeof(struct hkr_ring_desc) * hkr_dev->stream_nums);
#endif

	return 0;
}

static void hkr_assign_queue_ring_descs(struct hkr_device *hkr_dev,
                                        struct hkr_v4l2_queue *q, int idx)
{
	/* pass buffer num to client */
	q->ring_cpu_addr =
	        (struct hkr_ring_desc *) (hkr_dev->ring_cpu_addr +
	                                  (sizeof(struct hkr_ring_desc) * idx));

	q->ring_bus_addr = hkr_dev->ring_bus_addr +
	                   (sizeof(struct hkr_ring_desc) * idx);

	q->ring = (struct hkr_ring_desc *)q->ring_cpu_addr;

	q->ring->buf_num = HKR_MAX_BUFFER_NUM;
}

static void hkr_free_ring_descs(struct hkr_device *hkr_dev)
{
#ifdef DESC_RING_ON_HOST
	dma_free_coherent(hkr_dev->dev, hkr_dev->ring_org_size,
	                  hkr_dev->ring_cpu_org, hkr_dev->ring_bus_org);
#else
	HKR_INFO(hkr_dev->dev, "Ring desc on EP, no need to free\n");
#endif
}

static bool hkr_mbx_notify_ep(struct hkr_device *hkr_dev,
                              struct notify_param *params)
{
	struct pci_dev  *pdev = hkr_dev->pdev;

	/* reset header first */
	pci_write_config_dword(pdev, MBX_HEADER_VF1, 0x00);         /* Header */

	pci_write_config_dword(pdev, MBX_HEADER_VF1,
	                           params->header);        /* Header */
	pci_write_config_dword(pdev, MBX_PAYLOAD0_VF1,
	                           params->payload[0]); /* Payload 0 */
	pci_write_config_dword(pdev, MBX_PAYLOAD1_VF1,
	                           params->payload[1]); /* Payload 1 */
	pci_write_config_dword(pdev, MBX_PAYLOAD2_VF1,
	                           params->payload[2]); /* Payload 2 */
	pci_write_config_dword(pdev, MBX_PAYLOAD3_VF1,
	                           params->payload[3]); /* Payload 3 */
	pci_write_config_dword(pdev, MBX_PAYLOAD4_VF1,
	                           params->payload[4]); /* Payload 4 */
	pci_write_config_dword(pdev, MBX_PAYLOAD5_VF1,
	                           params->payload[5]); /* Payload 5 */
	pci_write_config_dword(pdev, MBX_PAYLOAD6_VF1,
	                           params->payload[6]); /* Payload 6 */
	pci_write_config_dword(pdev, MBX_PAYLOAD7_VF1,
	                           params->payload[7]); /* Payload 7 */

	return true;
}

static void hkr_queque_buf_notify(struct hkr_device *hkr_dev, int stream_idx)
{
	struct notify_param params = {};
	params.header = MBX_DEFAULT_HEADER;
	params.payload[0] = MBX_PL_TYPE_QUEUE_BUF;
	params.payload[1] = stream_idx;

	hkr_mbx_notify_ep(hkr_dev, &params);
}

static void hkr_init_host2dev_msg_buf(struct hkr_device *hkr_dev)
{
	struct hkr_msg_buf *msg_buf =
	        (struct hkr_msg_buf *)(hkr_dev->base + HKR_HOST2DEV_MSG_OFF);

	memset(msg_buf, 0, sizeof(*msg_buf));
	msg_buf->header.msg_num = MSG_ITEM_NUM;
	msg_buf->header.item_size =  MSG_ITEM_SIZE;

	hkr_dev->msg_buf = msg_buf;
}

static struct hkr_msg_item *hkr_get_msg_free_item(struct hkr_device *hkr_dev)
{
	struct hkr_msg_buf *msg_buf = hkr_dev->msg_buf;
	uint64_t idx, next_idx;

	idx = msg_buf->header.wr_idx;
	next_idx = (idx + 1) % (msg_buf->header.msg_num);
	if (next_idx == msg_buf->header.rd_idx) {
		HKR_INFO(hkr_dev->dev, "Error: msg queue full\n");
		return NULL;
	}

	/* Just return the item, write index will update after finishing
	 * written to the item.
	 */

	return &msg_buf->items[idx];
}

static void hkr_update_msg_wr_index(struct hkr_device *hkr_dev)
{
	struct hkr_msg_buf *msg_buf = hkr_dev->msg_buf;
	uint64_t idx, next_idx;

	idx = msg_buf->header.wr_idx;
	next_idx = (idx + 1) % (msg_buf->header.msg_num);

	msg_buf->header.wr_idx = next_idx;
}

static int hkr_send_mbx_message(struct hkr_device *hkr_dev,
                                struct hkr_msg_header *head)
{
	struct notify_param params = {};
	params.header = MBX_DEFAULT_HEADER;
	params.payload[0] = MBX_PL_TYPE_MSG;

	if (head->msg_size) {
		struct hkr_msg_item *item = hkr_get_msg_free_item(hkr_dev);
		if (item != NULL && head->msg_size <= sizeof(*item)) {
			memcpy((void *)item->data, (void *)head, head->msg_size);
			/* Update msg write index */
			hkr_update_msg_wr_index(hkr_dev);
			hkr_mbx_notify_ep(hkr_dev, &params);
		}
	}

	return 0;
}

int hkr_send_msg(struct hkr_device *hkr_dev,
                 struct hkr_msg_header *snd_header)
{
        struct hkr_msg_ack_header *header;
	uint32_t val;

	header = (struct hkr_msg_ack_header *)(hkr_dev->base +
	                                       HKR_DEV2HOST_MSG_OFF);
	mutex_lock(&hkr_dev->msg_lock);

	hkr_send_mbx_message(hkr_dev, snd_header);
#if 0
	val  = wait_for_completion_timeout(&hkr_dev->msg_ack_comp, msecs_to_jiffies(1000));
	if (!val) {
		mutex_unlock(&hkr_dev->msg_lock);
		return -ENODEV;
	}

	if (header->msg_size)
		memcpy(ack_header, header, header->msg_size);
#endif
	mutex_unlock(&hkr_dev->msg_lock);
	return 0;
}

/*
 * Called after each buffer is allocated. As we are using contiguous
 * memory, seems no special operation here.
 * TODO: remove this function later if no operation.
 */
static int hkr_vb2_buf_init(struct vb2_buffer *vb)
{
	struct hkr_device *hkr_dev = vb2_get_drv_priv(vb->vb2_queue);
	struct device *dev = hkr_dev->dev;

	HKR_INFO(dev, "init-index:%d type:%d memory:%d num_planes:%d\n",
	         vb->index, vb->type, vb->memory, vb->num_planes);

	HKR_INFO(dev, "init-vbuf_address:%p length:%d dma_buf:%p mapped:%d\n",
	         vb2_plane_vaddr(vb, 0), vb->planes[0].length,
	         vb->planes[0].dbuf, vb->planes[0].dbuf_mapped);

	return 0;
}
/*
 * Transfer buffer ownership to hkr. As we are using contiguous memory,
 * we need to put its head into queue.
 */

static void hkr_vb2_buf_queue(struct vb2_buffer *vb)
{
	int ret = 0;
	struct hkr_device *hkr_dev = vb2_get_drv_priv(vb->vb2_queue);
	struct device *dev = hkr_dev->dev;
	struct hkr_v4l2_queue *q =
	        container_of(vb->vb2_queue, struct hkr_v4l2_queue, vbq);
	struct hkr_buffer *b =
	        container_of(vb, struct hkr_buffer, vbb.vb2_buf);
	unsigned long flags;
	dma_addr_t dma_addr;

	HKR_INFO(dev, "%s %d b:%p buff:%p vb_index:%d\n", __func__, __LINE__,
	         b, q->bufs[q->enq_index], vb->index);

	dma_addr = vb2_dma_contig_plane_dma_addr(vb, 0);
	/* if we have empty position */
	local_irq_save(flags);
	if (!q->bufs[q->enq_index]) {
		q->bufs[q->enq_index] = b;
		HKR_INFO(dev, "enq_index:%d -->%p\n", q->enq_index,
		         q->bufs[q->enq_index]);
		q->enq_index = (q->enq_index + 1) % HKR_MAX_BUFFER_NUM;
		/* put dma address to ring */
		if (((q->ring->wr_index + 1) % HKR_MAX_BUFFER_NUM) ==
		                q->ring->rd_index) {
			dev_err(dev, "ring full. Should not happen");
		} else {
			q->ring->dma_addr[q->ring->wr_index] =
			        dma_addr;
			HKR_INFO(dev, "stream-%d ring:%p wr_index:%d rd_index:%d dma:%llx\n",
					q->stream_index, q->ring, q->ring->wr_index, q->ring->rd_index,
					q->ring->dma_addr[q->ring->wr_index]);
			q->ring->wr_index = (q->ring->wr_index + 1) %
			                    HKR_MAX_BUFFER_NUM;

			/* call wmb() to ensure write to memory */
			wmb();
		}
	} else {
		ret = -ENOMEM;
	}
	local_irq_restore(flags);

	if (!ret) {
		atomic_inc_return(&q->bufs_queued);
		HKR_INFO(dev, "one buffer queued\n");
	} else {
		vb2_buffer_done(vb, VB2_BUF_STATE_ERROR);
		HKR_INFO(dev, "No buffer queued\n");
	}

	hkr_queque_buf_notify(hkr_dev, q->stream_index);
	HKR_INFO(dev, "%s %d next:%d\n", __func__, __LINE__, q->enq_index);
}

/* Called when each buffer is freed */
static void hkr_vb2_buf_cleanup(struct vb2_buffer *vb)
{
}

/*
 * Called when VIDIOC_REQBUFS() and VIDIOC_CREATE_BUFS(). Return maximum
 * buffer number/planes supported by driver.
 */
static int hkr_vb2_queue_setup(struct vb2_queue *vq,
                               unsigned int *num_buffers,
                               unsigned int *num_planes,
                               unsigned int sizes[],
                               struct device *alloc_devs[])
{
	int i;
	struct hkr_device *hkr_dev = vb2_get_drv_priv(vq);
	struct device *dev = hkr_dev->dev;
	struct hkr_v4l2_queue *q = vb2q_to_hkr_v4l2_queue(vq);

	*num_planes = 1;

	for (i = 0; i < *num_planes; i++) {
		sizes[i] = q->format.sizeimage;
		alloc_devs[i] = dev;
		HKR_INFO(dev, "size[%d]:%d\n", i, sizes[i]);
	}

	/*
	 * TODO: should we make buffer HKR_MAX_BUFFER_NUM -1 to ensure
	 * always one buffer available.
	 */
	*num_buffers = clamp_val(*num_buffers, 1, HKR_MAX_BUFFER_NUM - 1);

	for (i = 0; i < HKR_MAX_BUFFER_NUM; i++)
		q->bufs[i] = NULL;

	q->deq_index = 0;
	q->enq_index = 0;
	q->ring->rd_index = 0;
	q->ring->wr_index = 0;
	atomic_set(&q->bufs_queued, 0);

	HKR_INFO(dev, "%s %d num_planes:%d num_buffer:%d\n", __func__,
	         __LINE__, *num_planes, *num_buffers);

	return 0;
}

/* start streaming */
static int hkr_vb2_start_streaming(struct vb2_queue *vq, unsigned int count)
{
	struct hkr_device *hkr_dev = vb2_get_drv_priv(vq);
	struct device *dev = hkr_dev->dev;
	struct hkr_v4l2_queue *q = vb2q_to_hkr_v4l2_queue(vq);
	struct hkr_msg_start message;
	int ret;

	message.header.msg_size = sizeof(message);
	message.header.msg_type = HKR_MSG_STREAM_START;
	message.num_of_stream = 1;
	message.stream_ids[0] = q->stream_index;

	ret = hkr_send_msg(hkr_dev, &message.header);
	wait_for_completion_timeout(&q->msg_ack_comp, msecs_to_jiffies(1000));

	return 0;
}

static void hkr_vb2_return_all_buffers(struct hkr_v4l2_queue *q,
                                       enum vb2_buffer_state state)
{
	unsigned int i;
	struct hkr_device *hkr_dev = vb2_get_drv_priv(&q->vbq);

	for (i = 0; i < HKR_MAX_BUFFER_NUM; i++) {

		HKR_INFO(hkr_dev->dev, "q->buf[%d]:%p\n", i, q->bufs[i]);

		if (q->bufs[i]) {
			atomic_dec(&q->bufs_queued);
			vb2_buffer_done(&q->bufs[i]->vbb.vb2_buf, state);
		}
	}
}
/* stop streaming */
static void hkr_vb2_stop_streaming(struct vb2_queue *vq)
{
	struct hkr_device *hkr_dev = vb2_get_drv_priv(vq);
	struct device *dev = hkr_dev->dev;
	struct hkr_v4l2_queue *q = vb2q_to_hkr_v4l2_queue(vq);
	struct hkr_msg_stop message;
	int ret = 0;

	message.header.msg_size = sizeof(message);
	message.header.msg_type = HKR_MSG_STREAM_STOP;
	message.num_of_stream = 1;
	message.stream_ids[0] = q->stream_index;

	ret = hkr_send_msg(hkr_dev, &message.header);
	wait_for_completion_timeout(&q->msg_ack_comp, msecs_to_jiffies(1000));
#if 0
	if (ret) {
		HKR_INFO(dev, "send message time out\n");
		return;
	}

	if (done.header.error_code == 0)
		HKR_INFO(dev, "start message send successfully\n");
#endif
	/*
	 * TODO: We simplely delay here to wait all interrupt done
	 * Should wait for EP to finish.
	 */
	hkr_vb2_return_all_buffers(q, VB2_BUF_STATE_ERROR);
}

static const struct vb2_ops hkr_vb2_ops = {
	.buf_init = hkr_vb2_buf_init,
	.buf_queue = hkr_vb2_buf_queue,
	.buf_cleanup = hkr_vb2_buf_cleanup,
	.queue_setup = hkr_vb2_queue_setup,
	.start_streaming = hkr_vb2_start_streaming,
	.stop_streaming = hkr_vb2_stop_streaming,
	.wait_prepare = vb2_ops_wait_prepare,
	.wait_finish = vb2_ops_wait_finish,
};

/**************** V4L2 interface ****************/

static int hkr_v4l2_querycap(struct file *file, void *fh,
                             struct v4l2_capability *cap)
{
	struct hkr_device *hkr_dev = video_drvdata(file);

	strscpy(cap->driver, HKR_DRIVER_NAME, sizeof(cap->driver));
	strscpy(cap->card, HKR_DEVICE_NAME, sizeof(cap->card));
	snprintf(cap->bus_info, sizeof(cap->bus_info),
	         "PCI:%s", pci_name(hkr_dev->pdev));

	return 0;
}

static int hkr_v4l2_enum_fmt(struct file *file, void *fh,
                             struct v4l2_fmtdesc *f)
{
	if (f->index >= ARRAY_SIZE(hkr_formats))
		return -EINVAL;

	f->pixelformat = hkr_formats[f->index].fourcc;

	return 0;
}

static int hkr_v4l2_g_fmt(struct file *file, void *fh, struct v4l2_format *f)
{
	struct hkr_v4l2_queue *q = file_to_hkr_v4l2_queue(file);

	f->fmt.pix = q->format;

	return 0;
}

/*
 * hkr_find_format - lookup color format by fourcc
 * @pixelformat: fourcc to match, ignored if null
 */
static const struct hkr_fmt *hkr_find_format(const unsigned int *pixelformat)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(hkr_formats); i++) {
		if (pixelformat && *pixelformat != hkr_formats[i].fourcc)
			continue;
		return &hkr_formats[i];
	}
	return NULL;
}

static int hkr_v4l2_try_fmt(struct file *file, void *fh, struct v4l2_format *f)
{
	const struct hkr_fmt *fmt;
	struct v4l2_pix_format *pix = &f->fmt.pix;

	fmt = hkr_find_format(&pix->pixelformat);
	if (!fmt) {
		printk("failed to find format, use default\n");
		fmt = &hkr_formats[0];
		pix->width=640;
		pix->height=480;
	}
	/* Only supports up to 1920x1080 */
	if (pix->width > HKR_MAX_WIDTH)
		pix->width = HKR_MAX_WIDTH;
	if (pix->height > HKR_MAX_HEIGHT)
		pix->height = HKR_MAX_HEIGHT;

	pix->pixelformat = fmt->fourcc;
	pix->colorspace = V4L2_COLORSPACE_DEFAULT;
	pix->field = V4L2_FIELD_ANY;
	pix->bytesperline = hkr_bytesperline(pix->pixelformat, pix->width);
	pix->sizeimage = pix->bytesperline * pix->height;

	/* use default */
	pix->ycbcr_enc = V4L2_YCBCR_ENC_DEFAULT;
	pix->quantization = V4L2_QUANTIZATION_DEFAULT;
	pix->xfer_func = V4L2_XFER_FUNC_DEFAULT;
	return 0;
}

static int hkr_v4l2_s_fmt(struct file *file, void *fh, struct v4l2_format *f)
{
	struct hkr_v4l2_queue *q = file_to_hkr_v4l2_queue(file);

	hkr_v4l2_try_fmt(file, fh, f);
	q->format = f->fmt.pix;

	return 0;
}

/* TODO: We should not enum input, delete later */
static int hkr_video_enum_input(struct file *file, void *fh,
                                struct v4l2_input *input)
{
	if (input->index > 0)
		return -EINVAL;

	strscpy(input->name, "camera", sizeof(input->name));
	input->type = V4L2_INPUT_TYPE_CAMERA;

	return 0;
}

static int hkr_video_g_input(struct file *file, void *fh,
                             unsigned int *input)
{
	*input = 0;

	return 0;
}

static int hkr_video_s_input(struct file *file, void *fh,
                             unsigned int input)
{
	return input == 0 ? 0 : -EINVAL;
}

static const struct v4l2_ioctl_ops hkr_v4l2_ioctl_ops = {
	.vidioc_querycap = hkr_v4l2_querycap,
	.vidioc_enum_fmt_vid_cap = hkr_v4l2_enum_fmt,
	.vidioc_g_fmt_vid_cap_mplane = hkr_v4l2_g_fmt,
	.vidioc_s_fmt_vid_cap_mplane = hkr_v4l2_s_fmt,
	.vidioc_g_fmt_vid_cap = hkr_v4l2_g_fmt,
	.vidioc_s_fmt_vid_cap = hkr_v4l2_s_fmt,
	.vidioc_try_fmt_vid_cap = hkr_v4l2_try_fmt,
	.vidioc_try_fmt_vid_cap_mplane = hkr_v4l2_try_fmt,
	.vidioc_reqbufs = vb2_ioctl_reqbufs,
	.vidioc_create_bufs = vb2_ioctl_create_bufs,
	.vidioc_prepare_buf = vb2_ioctl_prepare_buf,
	.vidioc_querybuf = vb2_ioctl_querybuf,
	.vidioc_qbuf = vb2_ioctl_qbuf,
	.vidioc_dqbuf = vb2_ioctl_dqbuf,
	.vidioc_streamon = vb2_ioctl_streamon,
	.vidioc_streamoff = vb2_ioctl_streamoff,
	.vidioc_expbuf = vb2_ioctl_expbuf,
	.vidioc_enum_input = hkr_video_enum_input,
	.vidioc_g_input	= hkr_video_g_input,
	.vidioc_s_input	= hkr_video_s_input,
};

static irqreturn_t hkr_irq(int irq, void *hkr_ptr)
{
	int deq_index;
	unsigned long flags;
	struct hkr_v4l2_queue *q = (struct hkr_v4l2_queue *) hkr_ptr;
	int bufs_queued = atomic_read(&q->bufs_queued);
	struct hkr_device *hkr_dev = vb2_get_drv_priv(&q->vbq);
	struct device *dev = hkr_dev->dev;
	struct vb2_buffer *vb;
	struct timespec64 timestamp;

	if (bufs_queued < 0) {
		dev_err(dev, " No buffer available\n");
		goto irq_done;
	}

	/*
	 * TODO: As no queue will be queued before queue is done.
	 * Is it necessary to do this here?
	 */

	local_irq_save(flags);
	deq_index = q->deq_index;
	local_irq_restore(flags);

	HKR_INFO(dev, "%s %d deq_index:%d\n", __func__, __LINE__, deq_index);

	if (q->bufs[deq_index]) {
		vb = &q->bufs[deq_index]->vbb.vb2_buf;
		ktime_get_coarse_real_ts64(&timestamp);
                vb->timestamp = timestamp.tv_sec*1000000000 + timestamp.tv_nsec;

		local_irq_save(flags);
		q->bufs[deq_index] = NULL;
		deq_index = (deq_index + 1) % HKR_MAX_BUFFER_NUM;
		q->deq_index = deq_index;
		local_irq_restore(flags);

		atomic_dec(&q->bufs_queued);
		vb2_buffer_done(vb, VB2_BUF_STATE_DONE);
		HKR_INFO(dev, "stream-%d one buffer done, dma addr %llx\n", q->stream_index,
                                                                q->ring->dma_addr[q->ring->rd_index]);
	}

	HKR_INFO(dev, "+++++%s %d next deq_index:%d\n", __func__, __LINE__,
	         q->deq_index);

irq_done:

	return IRQ_HANDLED;
}

static int get_dev2host_msg_item(struct hkr_device *hkr_dev, struct hkr_msg_item *item)
{
	uint64_t idx;
	struct hkr_msg_buf *msg_buf =
	        (struct hkr_msg_buf *)(hkr_dev->base + HKR_DEV2HOST_MSG_OFF);

	/* We get this message in IRQ context, no protection here. */
	idx = msg_buf->header.rd_idx;
	if (idx != msg_buf->header.wr_idx) {
		memcpy(item->data, msg_buf->items[idx].data, sizeof(*item));
		idx = (idx + 1) % (msg_buf->header.msg_num);

		msg_buf->header.rd_idx = idx;
		return 0;

	}

	return -EAGAIN;
}

static void hkr_process_start_ack(struct hkr_device *hkr_dev,
                                  struct hkr_msg_header *header)
{
	int i;
	int idx;
	struct hkr_msg_start_done *done = (struct hkr_msg_start_done *)header;

	for (i = 0; i < done->num_of_stream; i++) {
		idx = done->stream_ids[i];
		complete(&hkr_dev->queue[idx].msg_ack_comp);
	}
}

static void hkr_process_stop_ack(struct hkr_device *hkr_dev,
                                 struct hkr_msg_header *header)
{
	int i;
	int idx;
	struct hkr_msg_start_done *done = (struct hkr_msg_start_done *)header;

	for (i = 0; i < done->num_of_stream; i++) {
		idx = done->stream_ids[i];
		complete(&hkr_dev->queue[idx].msg_ack_comp);
	}
}

static void hkr_process_dev2host_message(struct hkr_device *hkr_dev)
{
	struct hkr_msg_item item;

	if (!(get_dev2host_msg_item(hkr_dev, &item))) {
		struct hkr_msg_header *header =
		        (struct hkr_msg_header *)item.data;
		switch (header->msg_type) {
		case HKR_MSG_STREAM_START_ACK:
			hkr_process_start_ack(hkr_dev, header);
			break;
		case HKR_MSG_STREAM_STOP_ACK:
			hkr_process_stop_ack(hkr_dev, header);
			break;
		}
	}
}
static irqreturn_t hkr_dev_msg_irq(int irq, void *hkr_ptr)
{
	int i;
	uint64_t single_mode_satus;
	uint64_t single_clear_status = 0;
	struct hkr_device *hkr_dev = (struct hkr_device *)hkr_ptr;

	single_mode_satus = readq(hkr_dev->base + HKR_EP_INT_STAUS_OFF);
	if ((hkr_dev->irq_mode == IRQ_MODE_MULTI) ||
	                ((hkr_dev->irq_mode == IRQ_MODE_SINGLE) &&
	                 (single_mode_satus & HKR_EP_INT_MSG))) {
		single_clear_status &= ~HKR_EP_INT_MSG;

		hkr_process_dev2host_message(hkr_dev);
	}

	/* Non message IRQ only handled here in IRQ_MODE_SINGLE */
	if (hkr_dev->irq_mode == IRQ_MODE_SINGLE) {
		int img_idx = 0, imu_idx = 0;
		for (i = 0; i < hkr_dev->stream_nums; i++) {
			if (single_mode_satus & HKR_EP_INT_FRAME(i)) {
				single_clear_status &= ~HKR_EP_INT_FRAME(i);
				if (hkr_dev->stream_type[i] == HKR_STREAM_IMAGE)
					hkr_irq(irq, &hkr_dev->queue[img_idx]);
#if 0
				else if (hkr_dev->stream_type[i] == HKR_STREAM_IMU) {
					hkr_hid_irq(irq, &hkr_dev->hid_data[imu_idx]);
				}
#endif
			}
			if (hkr_dev->stream_type[i] == HKR_STREAM_IMAGE)
				img_idx++;
			else if (hkr_dev->stream_type[i] == HKR_STREAM_IMU)
				imu_idx++;
		}
		/*
		 * TODO: Can this prevent IRQ missing or not? Need to evaluate.
		 */
		writeq(single_clear_status, hkr_dev->base + HKR_EP_INT_STAUS_OFF);
	}

	return IRQ_HANDLED;
}

static void hkr_destroy_v4l2_device(struct hkr_device *hkr_dev,
                                    struct hkr_v4l2_queue *q)
{
	free_irq(q->irq, q);
	video_unregister_device(&q->vdev);
	vb2_queue_release(&q->vbq);
	mutex_destroy(&q->lock);
}

static void hkr_destroy_v4l2_instances(struct hkr_device *hkr_dev)
{
	int i;

	for (i = 0; i < hkr_dev->image_stream_num; i++)
		hkr_destroy_v4l2_device(hkr_dev, &hkr_dev->queue[i]);
}

static int hkr_create_v4l2_device(struct hkr_device *hkr_dev,
                                  struct hkr_v4l2_queue *q, void *config)
{
	int err;
	struct device *dev = hkr_dev->dev;
	struct video_device *vdev = &q->vdev;
	struct vb2_queue *vbq = &q->vbq;
	struct hkr_cfg_info_header *header;
	struct hkr_image_stream *image_stream;

	mutex_init(&q->lock);
	header = (struct hkr_cfg_info_header *)config;

	if (header->type == HKR_STREAM_IMAGE) {
		image_stream = (struct hkr_image_stream *)config;
		q->format.width = image_stream->width;
		q->format.height = image_stream->height;
		q->format.pixelformat = image_stream->fourcc;
		q->format.colorspace = V4L2_COLORSPACE_DEFAULT;
		q->format.field = V4L2_FIELD_ANY;
		q->format.bytesperline = hkr_bytesperline(q->format.pixelformat,q->format.width);
		q->format.sizeimage = q->format.bytesperline * q->format.height;
		q->irq = hkr_dev->irq + image_stream->irq_index - 1;

		HKR_INFO(dev, "hkr_dev->irq:%d index:%d\n", hkr_dev->irq,
		         image_stream->irq_index);
	} else {
		HKR_INFO(dev, "we only support image stream now");
		return -EINVAL;
	}

	init_completion(&q->msg_ack_comp);

	HKR_INFO(dev, "cpu:%p dma:%llx\n", q->ring, q->ring_bus_addr);
	writel(q->ring_bus_addr & 0xFFFFFFFF,
	       q->base + HKR_DMA_DESC_LOW_OFF);

	writel(q->ring_bus_addr >> 32,
	       q->base + HKR_DMA_DESC_HIGH_OFF);

	/* TODO: may implement media framework or subdev later here */
	vbq->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

	/* TODO: How to implement user ptr when no IOMMU? */
	vbq->io_modes = VB2_MMAP;
	vbq->ops = &hkr_vb2_ops;
	vbq->mem_ops = &vb2_dma_contig_memops;
	vbq->buf_struct_size = sizeof(struct hkr_buffer);
	/* TODO: How to update time stamp from HKR? */
	vbq->timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
	vbq->min_buffers_needed = 2;
	vbq->drv_priv = hkr_dev;
	vbq->lock = &q->lock;
	err = vb2_queue_init(vbq);
	if (err) {
		dev_err(dev,
		        "Failed to initialize videobuf2 queue (%d)\n", err);
		goto fail_vbq;
	}

	/* Only support interrupt for each*/
	if (hkr_dev->irq_mode == IRQ_MODE_MULTI) {
		HKR_INFO(dev, "q:%px irq:%d\n", q, q->irq);
		err = request_irq(q->irq, hkr_irq, IRQF_SHARED,
		                  HKR_DRIVER_NAME, q);
		if (err) {
			/* when failed, devm will clean the irq */
			dev_err(dev, "failed to request IRQ (%d)\n", err);
			goto irq_fail;
		}
	}

	snprintf(vdev->name, sizeof(vdev->name), "%s-%td", HKR_DRIVER_NAME,
	         q - hkr_dev->queue);
	vdev->release = video_device_release_empty;
	vdev->fops = &hkr_v4l2_fops;
	vdev->ioctl_ops = &hkr_v4l2_ioctl_ops;
	vdev->lock = &hkr_dev->lock;
	vdev->v4l2_dev = &hkr_dev->v4l2_dev;
	/* binding queue */

	vdev->queue = &q->vbq;
	vdev->device_caps = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING;
	HKR_INFO(dev, "**device cap:%x\n", vdev->device_caps);
	video_set_drvdata(vdev, hkr_dev);
	err = video_register_device(vdev, VFL_TYPE_VIDEO, -1);
	if (err) {
		dev_err(dev,
		        "Failed to register video device(%d)\n", err);
		goto fail_vdev;
	}

	return 0;

irq_fail:
fail_vdev:
	free_irq(q->irq, q);
	vb2_queue_release(vbq);
fail_vbq:

	mutex_destroy(&q->lock);

	return err;
}

static int hkr_create_v4l2_instances(struct hkr_device *hkr_dev)
{
	int idx = 0, err = 0;
	int stream_idx;
	struct device *dev = hkr_dev->dev;
	struct hkr_stream_item *item;
	struct hkr_image_stream *stream;

	snprintf(hkr_dev->v4l2_dev.name, sizeof(hkr_dev->v4l2_dev.name),
	         "%s", HKR_DRIVER_NAME);
	err = v4l2_device_register(dev, &hkr_dev->v4l2_dev);
	if (err) {
		dev_err(dev, "Failed to register v4l2 device.\n");
		return err;
	}

	list_for_each_entry(item, &hkr_dev->image_streams, list) {
		stream = (struct hkr_image_stream *)item->stream;

		stream_idx = stream->stream_index;
		hkr_dev->queue[idx].stream_index = stream_idx;
		hkr_assign_queue_ring_descs(hkr_dev, &hkr_dev->queue[idx],
		                            stream_idx);
		hkr_dev->queue[idx].base = hkr_dev->base +
		                           HKR_STREAM_CRTL_OFF(stream_idx);
		err = hkr_create_v4l2_device(hkr_dev, &hkr_dev->queue[idx],
		                             item->stream);

		if (err)
			break;

		idx++;
	}

	hkr_dev->image_stream_num = idx;

	if (hkr_dev->image_stream_num > HKR_MAX_STREAM_NUM) {
		err = -EINVAL;
		dev_err(dev, "Stream number %d overflows maximum:%d\n",
		        hkr_dev->image_stream_num, HKR_MAX_STREAM_NUM);
	}

	if (err) {
		for (idx--; idx >= 0; idx--)
			hkr_destroy_v4l2_device(hkr_dev, &hkr_dev->queue[idx]);
	}

	return err;
}

static void hkr_assign_hid_ring_descs(struct hkr_device *hkr_dev,
                                      struct hkr_hid_data *hid_data, int idx)
{
	/* pass buffer num to client */
	hid_data->ring_cpu_addr =
	        (struct hkr_ring_desc *) (hkr_dev->ring_cpu_addr +
	                                  (sizeof(struct hkr_ring_desc) * idx));

	hid_data->ring_bus_addr = hkr_dev->ring_bus_addr +
	                          (sizeof(struct hkr_ring_desc) * idx);

	hid_data->ring = hid_data->ring_cpu_addr;

	hid_data->ring->buf_num = HKR_MAX_BUFFER_NUM;
}

static void hkr_destroy_hid_device(struct hkr_hid_data *hid_data)
{
	hkr_hid_remove(hid_data);
}

static void hkr_destroy_hid_instances(struct hkr_device *hkr_dev)
{
	int i;

	for (i = 0; i < hkr_dev->imu_stream_num; i++)
		hkr_destroy_hid_device(&hkr_dev->hid_data[i]);
}

static int hkr_create_hid_instances(struct hkr_device *hkr_dev)
{
	int idx = 0, err = 0;
	int stream_idx;
	struct device *dev = hkr_dev->dev;
	struct hkr_stream_item *item;
	struct hkr_imu_stream *stream;

	list_for_each_entry(item, &hkr_dev->imu_streams, list) {
		stream = (struct hkr_imu_stream *)item->stream;

		stream_idx = stream->stream_index;
		hkr_dev->hid_data[idx].stream_id = stream_idx;
		hkr_dev->hid_data[idx].irq = hkr_dev->irq +
		                             stream->irq_index - 1;
		hkr_dev->hid_data[idx].hkr_dev = hkr_dev;
		hkr_dev->hid_data[idx].parent_dev = hkr_dev->dev;
		hkr_dev->hid_data[idx].buf_size =
		        (stream->size < hkr_dev->alignment) ?
		        hkr_dev->alignment : stream->size;

		hkr_assign_hid_ring_descs(hkr_dev, &hkr_dev->hid_data[idx],
		                          stream_idx);
		hkr_dev->hid_data[idx].base = hkr_dev->base +
		                              HKR_STREAM_CRTL_OFF(stream_idx);

		err = hkr_create_hid_device(&hkr_dev->hid_data[idx]);
		if (err) {
			dev_err(dev, "create hid device failed\n");
			break;
		}

		idx++;
	}

	hkr_dev->imu_stream_num = idx;

	if (hkr_dev->imu_stream_num > HKR_MAX_STREAM_NUM) {
		err = -EINVAL;
		dev_err(dev, "Stream number %d overflows maximum:%d\n",
		        hkr_dev->imu_stream_num, HKR_MAX_STREAM_NUM);
	}

	if (err) {
		for (idx--; idx >= 0; idx--)
			hkr_destroy_hid_device(&hkr_dev->hid_data[idx]);
	}

	return err;
}

static void hkr_destroy_instances(struct hkr_device *hkr_dev)
{
	hkr_destroy_v4l2_instances(hkr_dev);
	hkr_destroy_hid_instances(hkr_dev);
}

static int hkr_create_instances(struct hkr_device *hkr_dev)
{
	int err = 0;
	struct device *dev = hkr_dev->dev;

	err = hkr_alloc_ring_descs(hkr_dev);
	if (err) {
		dev_err(dev, "alloc ring descriptor buffers failed.\n");
		return err;
	}

	err =  hkr_create_v4l2_instances(hkr_dev);
	if (err) {
		dev_err(dev, "create v4l2 devices failed\n");
		goto create_v4l2_err;
	}

#if 0
	err = hkr_create_hid_instances(hkr_dev);
	if (err) {
		dev_err(dev, "create hid devices failed\n");
		goto create_hid_err;
	}
#endif
	writel(hkr_dev->ring_bus_addr & 0xFFFFFFFF,
	       hkr_dev->base + HKR_RING_DESCS_LOW_OFF);
	writel(hkr_dev->ring_bus_addr >> 32,
	       hkr_dev->base + HKR_RING_DESCS_HIGH_OFF);

	writel(hkr_dev->each_ring_size & 0xFFFFFFFF,
	       hkr_dev->base + HKR_RING_EACH_SIZE_OFF);

	HKR_INFO(dev, "%d streams registered ring_base:%llx\n",
	         hkr_dev->image_stream_num, hkr_dev->ring_bus_addr);
	return 0;

create_hid_err:
	hkr_destroy_v4l2_instances(hkr_dev);
create_v4l2_err:
	hkr_free_ring_descs(hkr_dev);
	return err;
}

static void hkr_free_stream_list(struct list_head *head)
{
	struct hkr_stream_item *item, *tmp;

	list_for_each_entry_safe(item, tmp, head, list) {
		kfree(item->stream);
		list_del(&item->list);
		kfree(item);
	}
}

static void hkr_destroy_item_list(struct hkr_device *hkr_dev)
{
	hkr_free_stream_list(&hkr_dev->image_streams);
	hkr_free_stream_list(&hkr_dev->meta_streams);
	hkr_free_stream_list(&hkr_dev->imu_streams);
}

/* Copy image stream data from register to normal memory */
static int hkr_add_image_item(struct hkr_device *hkr_dev, void *base)
{
	struct hkr_image_stream *stream;
	struct hkr_stream_item *item;

	stream = kmalloc(sizeof(*stream), GFP_KERNEL);
	if (!stream)
		return -ENOMEM;

	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (!item) {
		kfree(stream);
		return -ENOMEM;
	}

	memcpy_fromio(stream, base, sizeof(*stream));
	item->stream = (void *)stream;
	list_add_tail(&item->list, &hkr_dev->image_streams);

	HKR_INFO(hkr_dev->dev,
	         "add image item, width:%d height:%d depth:%d fourcc:%x",
	         stream->width, stream->height, stream->depth, stream->fourcc);

	return 0;
}

/* Copy meta stream data from register to normal memory */
static int hkr_add_meta_item(struct hkr_device *hkr_dev, void *base)
{
	struct hkr_meta_stream *stream;
	struct hkr_stream_item *item;

	stream = kmalloc(sizeof(*stream), GFP_KERNEL);
	if (!stream)
		return -ENOMEM;

	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (!item) {
		kfree(stream);
		return -ENOMEM;
	}

	memcpy_fromio(stream, base, sizeof(*stream));
	item->stream = (void *)stream;
	list_add_tail(&item->list, &hkr_dev->meta_streams);

	HKR_INFO(hkr_dev->dev, "add meta item, type:%x size:%d",
	         stream->header.type, stream->header.size);

	return 0;
}

/* Copy meta stream data from register to normal memory */
static int hkr_add_imu_item(struct hkr_device *hkr_dev, void *base)
{
	struct hkr_imu_stream *stream;
	struct hkr_stream_item *item;

	stream = kmalloc(sizeof(*stream), GFP_KERNEL);
	if (!stream)
		return -ENOMEM;

	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (!item) {
		kfree(stream);
		return -ENOMEM;
	}

	memcpy_fromio(stream, base, sizeof(*stream));
	item->stream = (void *)stream;
	list_add_tail(&item->list, &hkr_dev->imu_streams);

	HKR_INFO(hkr_dev->dev, "add imu item, type:%x size:%d",
	         stream->header.type, stream->header.size);

	return 0;
}

static int hkr_parse_usecase(struct hkr_device *hkr_dev)
{
	int i, ret = 0;
	int stream_num;
	struct hkr_cfg_info_header *header;
	struct hkr_device_config *config;
	struct device *dev = hkr_dev->dev;
	struct hkr_device_info *info;
	struct hkr_usecase_info *usecase_info;
	void *base = hkr_dev->base + HKR_DEVICE_INFO_OFF;

	config = (struct hkr_device_config *)base;
	info = &config->device_info;
	HKR_INFO(dev, "config:%p\n", config);
	HKR_INFO(dev, "hkr versions:\n");
	HKR_INFO(dev, "hw: %x fw:%x sw:%x\n", info->hw_version,
	         info->fw_version, info->sw_version);
	HKR_INFO(dev, "hkr camera use case supported:%d\n",
	         config->usecase_num);

	hkr_dev->dev_info.esw_version = info->sw_version;
	hkr_dev->dev_info.fw_version = info->fw_version;
	hkr_dev->dev_info.hw_version = info->hw_version;

	base += sizeof(*config);
	usecase_info = (struct hkr_usecase_info *)base;
	stream_num = usecase_info->stream_num;
	HKR_INFO(dev, "usecase type:%d stream_num:%d base:%p\n",
	         usecase_info->header.type, stream_num, base);
	/* move to image/meta stream */
	base = (void *)(usecase_info + 1);
	for (i = 0; i < stream_num; i++) {
		HKR_INFO(dev, "anaysis stream:%d\n", i);
		header = (struct hkr_cfg_info_header *)base;
		HKR_INFO(dev, "i:%d type:%x size:%d\n", i, header->type,
		         header->size);

		hkr_dev->stream_type[i] = header->type;

		switch (header->type) {
		case HKR_STREAM_IMAGE:
			ret = hkr_add_image_item(hkr_dev, base);
			break;
		case HKR_STREAM_META:
			ret = hkr_add_meta_item(hkr_dev, base);
			break;
		case HKR_STREAM_IMU:
			ret = hkr_add_imu_item(hkr_dev, base);
			break;
		default:
			ret = -EINVAL;
			HKR_INFO(dev, "stream not supported\n");
			break;
		}

		if (ret)
			break;

		base = base + header->size;
	}

	hkr_dev->stream_nums = stream_num;
	/* destroy list if parse failed */
	if (ret) {
		hkr_destroy_item_list(hkr_dev);
	}

	return ret;
}

static inline struct hkr_control_dev *hkr_inode_to_ctl_dev(struct inode *inode)
{
	return container_of(inode->i_cdev, struct hkr_control_dev, cdev);
}

static inline struct hkr_device *hkr_ctl_to_hkr_dev(
        struct hkr_control_dev *ctl_dev)
{
	return container_of(ctl_dev, struct hkr_device, ctl_dev);
}

static int hkr_ctl_open(struct inode *inode, struct file *file)
{
	struct hkr_control_dev *ctl_dev = hkr_inode_to_ctl_dev(inode);
	struct hkr_device *hkr_dev = hkr_ctl_to_hkr_dev(ctl_dev);

	file->private_data = hkr_dev;

	HKR_INFO(hkr_dev->dev, "major:%d\n", ctl_dev->major);

	return nonseekable_open(inode, file);
}

enum {
	HKR_PCIE_CTL_GET_DEV_INFO,
	HKR_PCIE_CTL_DEVICE_RST,
	HKR_PCIE_CTL_GET_UC_CFG,
	HKR_PCIE_CTL_SET_UC,
};

enum {
	HKR_PCIE_MON_TRACE_CTL,
	HKr_PCIE_MON_TRACE_GRAB
};

static int hkr_ctl_release(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t hkr_ctl_write(struct file *file, const char __user *data,
                             size_t len, loff_t *ppos)
{
	return 0;
}

static ssize_t hkr_ctl_read(struct file *file, char __user *buf,
                            size_t len, loff_t *ppos)
{
	return 0;
}

static int hkr_ctrl_reset_device(struct hkr_device *hkr_dev)
{
	/* inform client probe is done */
	writel(HKR_REST_DEVICE_BIT,
	       hkr_dev->base + HKR_RST_DEVICE_OFF);

	return 0;
}

static inline unsigned long hkr_copy_device_info(struct hkr_device *hkr_dev,
                unsigned long arg)
{
	int bytes;

	bytes = copy_to_user((void __user *)arg, &hkr_dev->dev_info,
	                     sizeof(struct hkr_pcie_device_info));

	if (bytes)
		return -EFAULT;

	return 0;
}

static long hkr_ctl_ioctl(struct file *filp, unsigned int cmd,
                          unsigned long arg)
{
	int ret = 0;
	struct hkr_device *hkr_dev = (struct hkr_device *)filp->private_data;
	struct device *dev = hkr_dev->dev;

	switch (cmd) {
	case HKR_PCIE_CTL_GET_DEV_INFO:
		ret = hkr_copy_device_info(hkr_dev, arg);
		break;
	case HKR_PCIE_CTL_DEVICE_RST:
		ret = hkr_ctrl_reset_device(hkr_dev);
		break;
	default:
		HKR_INFO(dev, "unsupported I/O control\n");
		break;
	}

	return ret;
}

static const struct file_operations hkr_ctl_fileops = {
	.owner   = THIS_MODULE,
	.write   = hkr_ctl_write,
	.read    = hkr_ctl_read,
	.unlocked_ioctl = hkr_ctl_ioctl,
	.open    = hkr_ctl_open,
	.release = hkr_ctl_release,
	.llseek  = no_llseek,
};

static void hkr_destroy_ctl_device(struct hkr_device *hkr_dev)
{
	struct hkr_control_dev *ctl_dev = &hkr_dev->ctl_dev;

	device_destroy(ctl_dev->class, ctl_dev->devid);
	class_destroy(ctl_dev->class);
	cdev_del(&ctl_dev->cdev);
	/* cdev_put(&cdev_hello_cdev); */

	unregister_chrdev_region(MKDEV(ctl_dev->major, 0), 1);
}

static int hkr_create_ctl_device(struct hkr_device *hkr_dev)
{
	int ret = 0;
	struct hkr_control_dev *ctl_dev = &hkr_dev->ctl_dev;
	struct cdev *chr_dev = &ctl_dev->cdev;
	struct device *dev = hkr_dev->dev;

	ret = alloc_chrdev_region(&ctl_dev->devid, 0, 1,
	                          HKR_CTRL_DRIVER_NAME);
	ctl_dev->major = MAJOR(ctl_dev->devid);

	if (ret < 0) {
		dev_err(dev, "register ctl_dev region failed: %d\n", ret);
		return -ENOMEM;
	}

	HKR_INFO(dev, "HKR ctl_dev major:%d\n", ctl_dev->major);
	cdev_init(chr_dev, &hkr_ctl_fileops);
	ret = cdev_add(chr_dev, ctl_dev->devid, 1);
	if (ret) {
		dev_err(dev, "add cdev failed\n");
		goto undo_register_region;
	}

	ctl_dev->class = class_create(THIS_MODULE, HKR_CTRL_DRIVER_NAME);
	if (IS_ERR(ctl_dev->class)) {
		dev_err(dev, "create class failed\n");
		goto undo_cdev_add;
	}

	ctl_dev->dev = device_create(ctl_dev->class, NULL,
	                             ctl_dev->devid,
	                             NULL, HKR_CTRL_DRIVER_NAME);
	if (IS_ERR(ctl_dev->dev)) {
		dev_err(dev, "failed to create device\n");
		goto undor_create_class;
	}

	dev_info(dev, "%s register done\n", HKR_CTRL_DRIVER_NAME);
	return 0; /* succeed */

undor_create_class:
	class_destroy(ctl_dev->class);
undo_cdev_add:
	cdev_del(&ctl_dev->cdev);
undo_register_region:
	unregister_chrdev_region(ctl_dev->devid, 1);

	return ret;
}

void hkr_notify_host_state(struct hkr_device *hkr_dev, unsigned int state)
{
	/* inform client probe status */
	writel(state, hkr_dev->base + HKR_HOST_DRV_STAT_OFF);
}

static int hkr_probe(struct pci_dev *pdev,
                     const struct pci_device_id *id)
{
	int err = 0;
	unsigned int probe_state = 0;
	void __iomem *base;
	struct device *dev = &pdev->dev;
	struct hkr_device *hkr_dev;
	int irq_nums;
	struct hkr_pci_drv_data *data;

	HKR_INFO(dev, "HKR PCIE driver version: %d.%d.%d\n",
	         HKR_DRV_VERSION_MAJOR, HKR_DRV_VERSION_MINOR,
	         HKR_DRV_VERSION_CHG);

	hkr_dev = devm_kzalloc(dev, sizeof(*hkr_dev), GFP_KERNEL);
	if (!hkr_dev)
		return -ENOMEM;

	hkr_dev->pdev = pdev;
	hkr_dev->dev = dev;

	hkr_dev->dev_info.host_drv_version = (HKR_DRV_VERSION_MAJOR << 20) |
	                                     (HKR_DRV_VERSION_MINOR << 10) | (HKR_DRV_VERSION_CHG);

	strncpy(hkr_dev->dev_info.name, "hrk-v00", HKR_DEV_NAME_LENGTH);

	mutex_init(&hkr_dev->msg_lock);

	data = (struct hkr_pci_drv_data *) id->driver_data;
	if (data)
		hkr_dev->alignment = data->alignment;
	else
		hkr_dev->alignment = PAGE_SIZE;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Cannot enable HKR PCI device\n");
		return err;
	}

	err = pci_request_regions(pdev, HKR_DRIVER_NAME);
	if (err) {
		dev_err(dev, "Cannot obtain HKR PCI resource\n");
		goto err_disable_dev;
	}

	pci_set_master(pdev);
	irq_nums = pci_alloc_irq_vectors(pdev, 1, 32, PCI_IRQ_MSI);
	if (irq_nums < 0) {
		err = irq_nums;
		dev_err(dev, "HKR alloc irq vectors failed\n");
		goto alloc_irq_fail;
	}

	HKR_INFO(dev, "%d irqs found\n", irq_nums);
	hkr_dev->irq_nums = irq_nums;
	hkr_dev->irq = pci_irq_vector(pdev, 0); /* irq base */
	HKR_INFO(dev, "%s %d pdev->irq:%d hkr_dev->irq:%d\n", __func__,
	         __LINE__, pdev->irq, hkr_dev->irq);

	if (hkr_dev->irq_nums == 1) {
		hkr_dev->irq_mode = IRQ_MODE_SINGLE;
	} else {
		hkr_dev->irq_mode = IRQ_MODE_MULTI;
	}

	HKR_INFO(dev, "%s %d irq_mode:%d\n", __func__,
	         __LINE__, hkr_dev->irq_mode);

	/* we map bar0 as control and data exchange */
	if (pci_resource_flags(pdev, BAR_0) & IORESOURCE_MEM) {
		base = pci_ioremap_bar(pdev, BAR_0);
		if (!base) {
			dev_err(dev, "Failed to map bar0\n");
			err = -ENODEV;
			goto ioremap_err;
		}
		hkr_dev->base = base;
	}
	err = dma_set_mask_and_coherent(&pdev->dev, HKR_DMA_MASK);
	if (err) {
		err = -ENODEV;
		goto ioremap_err;
	}

	pci_set_drvdata(pdev, hkr_dev);

	{
		/* TODO: remove or add an output */
		struct resource *res = &pdev->resource[0];

		dev_err(dev, "start:%pR\n", res);
	}

	/* TODO: If each device is independent, should we use multiple lock? */
	mutex_init(&hkr_dev->lock);

	INIT_LIST_HEAD(&hkr_dev->image_streams);
	INIT_LIST_HEAD(&hkr_dev->meta_streams);
	INIT_LIST_HEAD(&hkr_dev->imu_streams);

	err = hkr_parse_usecase(hkr_dev);
	if (err) {
		dev_err(dev, "parse usecase fail\n");
		goto parse_usecase_fail;
	}

	hkr_init_host2dev_msg_buf(hkr_dev);
	err = request_irq(hkr_dev->irq, hkr_dev_msg_irq,
	                  0, HKR_DRIVER_NAME, hkr_dev);

	if (err) {
		dev_err(dev, "request msg irq failed\n");
		goto get_msg_irq_failed;
	}

	probe_state |= HKR_HOST_STAT_IRQ_INIT_DONE;
	hkr_notify_host_state(hkr_dev, probe_state);

	err = hkr_create_instances(hkr_dev);
	if (err) {
		dev_err(dev, "create instance failed\n");
		goto create_inst_fail;
	}

	err = hkr_create_ctl_device(hkr_dev);
	if (err) {
		dev_err(dev, "create ctrl device failed\n");
		goto create_ctrl_failed;
	}

	probe_state |= HKR_HOST_STAT_PROBE_DONE;
	hkr_notify_host_state(hkr_dev, probe_state);

	return 0;

create_ctrl_failed:
	hkr_destroy_instances(hkr_dev);
create_inst_fail:
	free_irq(hkr_dev->irq, hkr_dev);
get_msg_irq_failed:
parse_usecase_fail:
ioremap_err:
alloc_irq_fail:
	pci_free_irq_vectors(pdev);
	pci_release_regions(pdev);

err_disable_dev:
	pci_disable_device(pdev);

	return err;
}

static void hkr_remove(struct pci_dev *pdev)
{
	/* TODO: rmmod log: no resource to release [start...end] */
	struct device *dev = &pdev->dev;
	struct hkr_device *hkr_dev = (struct hkr_device *)pci_get_drvdata(pdev);

	hkr_destroy_ctl_device(hkr_dev);

	hkr_destroy_item_list(hkr_dev);
	hkr_destroy_instances(hkr_dev);
	hkr_free_ring_descs(hkr_dev);
	iounmap(hkr_dev->base);

	free_irq(hkr_dev->irq, hkr_dev);

	pci_free_irq_vectors(pdev);
	pci_release_regions(pdev);
	pci_disable_device(pdev);

	HKR_INFO(dev, "device removed free irq vectors 1104 disable msi\n");
}

static struct hkr_pci_drv_data hkr_drv_data = {
	.alignment = SZ_64K,
};

static const struct pci_device_id hkr_pci_id_table[] = {
	{	PCI_DEVICE(HKR_VENDOR_ID, HKR_PRODUCT_ID),
		.driver_data = (kernel_ulong_t)&hkr_drv_data
	},
};

static struct pci_driver hkr_pci_driver = {
	.name = HKR_DRIVER_NAME,
	.id_table = hkr_pci_id_table,
	.probe = hkr_probe,
	.remove = hkr_remove,
};

module_pci_driver(hkr_pci_driver);

MODULE_AUTHOR("Shunyong Yang <shunyong.yang@intel.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("HKR camera driver");
