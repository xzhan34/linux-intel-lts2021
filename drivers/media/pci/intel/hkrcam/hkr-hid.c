#include <linux/delay.h>
#include <linux/hid.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/pci.h>
#include <linux/pci-epf.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/property.h>
#include <linux/vmalloc.h>
/* These v4l2 include file will remove later */
#include <media/v4l2-ctrls.h>
#include <media/v4l2-device.h>
#include <media/v4l2-event.h>
#include <media/v4l2-fwnode.h>
#include <media/v4l2-ioctl.h>
#include <media/videobuf2-dma-contig.h>

#include "hkr-pcie-hostdev.h"
#include "hkr-hid.h"
#include "hkr-cam.h"

#define HKR_HID_NAME "hkr-hid"

#define MIN(a, b) ((a) < (b) ? (a):(b))

/* read report descriptor and parse */
static int hkr_hid_parse(struct hid_device *hid)
{
	int ret;
	struct hkr_msg_imu_get_desc cmd_msg = {};
	struct hkr_msg_imu_get_desc_done done_msg = {};
	struct hkr_hid_data *hid_data =
	        (struct hkr_hid_data *)hid->driver_data;

	cmd_msg.header.msg_type = HKR_MSG_IMU_GET_DESC;
	cmd_msg.header.msg_size = sizeof(cmd_msg);
	cmd_msg.stream_id = hid_data->stream_id;

#if 0
	hkr_send_msg_and_wait_ack(hid_data->hkr_dev, &cmd_msg.header,
	                          &done_msg.header);
#endif

	ret = hid_parse_report(hid, done_msg.desc, done_msg.desc_size);

	return 0;
}

/* keep for further usage */
static int hkr_hid_start(struct hid_device *hid)
{
	hid->claimed = 1;
	return 0;
}

/* keep for further usage */
static void hkr_hid_stop(struct hid_device *hid)
{
	hid->claimed = 0;
}

/* keep for further usage */
static int hkr_hid_open(struct hid_device *hid)
{
	return 0;
}

/* keep for further usage */
static void hkr_hid_close(struct hid_device *hid)
{
}

/* keep for further usage */
static int hkr_hid_output_report(struct hid_device *hid, __u8 *buf,
                                 size_t count)
{
	return 0;
}

static int hkr_hid_get_raw_report(struct hid_device *hid,
                                  unsigned char report_number, __u8 *buf, size_t count,
                                  unsigned char report_type)
{
	int size;
	int ret;
	struct hkr_msg_imu_get_report cmd_msg;
	struct hkr_msg_imu_get_report_done done_msg = {};
	struct hkr_hid_data *hid_data =
	        (struct hkr_hid_data *)hid->driver_data;

	if (report_type == HID_OUTPUT_REPORT)
		return -EINVAL;

	cmd_msg.header.msg_type = HKR_MSG_IMU_GET_REPORT;
	cmd_msg.header.msg_size = sizeof(cmd_msg);
	cmd_msg.count = count;
	cmd_msg.report_id = report_number;
	cmd_msg.report_type = report_type;
	cmd_msg.stream_id = hid_data->stream_id;

#if 0
	ret = hkr_send_msg_and_wait_ack(hid_data->hkr_dev, &cmd_msg.header,
	                                &done_msg.header);
	if (ret)
		return ret;
#endif

	size = MIN(count, done_msg.report_size);
	memcpy(buf, done_msg.report, size);

	return size;
}

static int hkr_hid_output_raw_report(struct hid_device *hid, __u8 *buf,
                                     size_t count, unsigned char report_type, bool use_data)
{
	int ret;
	struct hkr_msg_imu_set_report cmd_msg;
	struct hkr_msg_imu_set_report_done done_msg;
	struct hkr_hid_data *hid_data =
	        (struct hkr_hid_data *)hid->driver_data;

	if (report_type == HID_INPUT_REPORT)
		return -EINVAL;

	cmd_msg.header.msg_type = HKR_MSG_IMU_SET_REPORT;
	cmd_msg.header.msg_size = sizeof(cmd_msg);
	cmd_msg.report_id = buf[0];
	cmd_msg.report_size = count;
	cmd_msg.report_type = report_type;
	cmd_msg.stream_id = hid_data->stream_id;
	memcpy(cmd_msg.report, buf, count);

#if 0
	ret = hkr_send_msg_and_wait_ack(hid_data->hkr_dev, &cmd_msg.header,
	                                &done_msg.header);

	if (ret)
		return 0;
#endif

	return count;
}

/*
 * reportnum: report ID
 * rtype:
 *		#define HID_INPUT_REPORT	0
 *		#define HID_OUTPUT_REPORT	1
 *		#define HID_FEATURE_REPORT	2
 * reqtype:
 *		#define HID_REQ_GET_REPORT		0x01
 *		#define HID_REQ_GET_IDLE		0x02
 *		#define HID_REQ_GET_PROTOCOL		0x03
 *		#define HID_REQ_SET_REPORT		0x09
 *		#define HID_REQ_SET_IDLE		0x0A
 *		#define HID_REQ_SET_PROTOCOL		0x0B
 */

static int hkr_hid_raw_request(struct hid_device *hid, unsigned char reportnum,
                               __u8 *buf, size_t len, unsigned char rtype,
                               int reqtype)
{
	switch (reqtype) {
	case HID_REQ_GET_REPORT:
		return hkr_hid_get_raw_report(hid, reportnum, buf, len, rtype);
	case HID_REQ_SET_REPORT:
		if (buf[0] != reportnum)
			return -EINVAL;
		return hkr_hid_output_raw_report(hid, buf, len, rtype, true);
	default:
		return -EIO;
	}
}
irqreturn_t hkr_hid_irq(int irq, void *data)
{
	struct hkr_hid_data *hid_data = (struct hkr_hid_data *) data;
	unsigned char *report_data;
	int wr_index, rd_index;

	wr_index = hid_data->ring->wr_index;
	rd_index = hid_data->ring->rd_index;

	if (wr_index != rd_index) {
		report_data = (unsigned char *)
		              hid_data->ring->cpu_addr[rd_index];
		/* TODO: add header for type size */
		hid_input_report(hid_data->hid, HID_INPUT_REPORT, report_data,
		                 32, 1);

		rd_index = (rd_index + 1) % hid_data->ring->buf_num;
		hid_data->ring->rd_index = rd_index;
	}

	return IRQ_HANDLED;
}

static struct hid_ll_driver hkr_hid_ll_driver = {
	.parse = hkr_hid_parse,
	.start = hkr_hid_start,
	.stop = hkr_hid_stop,
	.open = hkr_hid_open,
	.close = hkr_hid_close,
	.output_report = hkr_hid_output_report,
	.raw_request = hkr_hid_raw_request,
};

static int hkr_hid_alloc_data_buffers(struct hkr_hid_data *hid_data)
{
	int i, err = 0;
	struct hkr_ring_desc *ring;

	ring = hid_data->ring;
	for (i = 0; i < hid_data->ring->buf_num; i++) {
		ring->cpu_addr[i] = (uint64_t)dma_alloc_coherent(
		                            hid_data->parent_dev, hid_data->buf_size,
		                            (dma_addr_t *)&ring->dma_addr[i],
		                            GFP_KERNEL);

		if (!ring->cpu_addr[i]) {
			err = -ENOMEM;
			break;
		}
	}

	if (err) {
		for (i--; i >= 0; i--)
			dma_free_coherent(hid_data->parent_dev,
			                  hid_data->buf_size,
			                  (void *)ring->cpu_addr[i],
			                  ring->dma_addr[i]);
	}

	ring->rd_index = 0;
	ring->wr_index = 0;

	return err;
}

void hkr_hid_free_data_buffers(struct hkr_hid_data *hid_data)
{
	int i;
	struct hkr_ring_desc *ring = hid_data->ring;

	for (i = 0; i < hid_data->ring->buf_num; i++)
		dma_free_coherent(hid_data->parent_dev, hid_data->buf_size,
		                  (void *)ring->cpu_addr[i], ring->dma_addr[i]);
}

int hkr_create_hid_device(struct hkr_hid_data *hid_data)
{
	int err = 0;
	struct hid_device *hid;

	hid = hid_allocate_device();
	if (IS_ERR(hid)) {
		dev_err(hid_data->parent_dev, "alloc HID device failed\n");
		return PTR_ERR(hid);
	}

	hid_data->hid = hid;
	hid->driver_data = hid_data;
	hid->ll_driver = &hkr_hid_ll_driver;
	hid->bus = BUS_HOST;
	hid->version = le16_to_cpu(0x001);
	hid->vendor = 0x8086;
	hid->product = 0x0022;

	err = hkr_hid_alloc_data_buffers(hid_data);
	if (err) {
		dev_err(hid_data->parent_dev, "alloc data buffer failed\n");
		goto err_alloc_buff;
	}

	/*
	 * We only register irq when multiple MSI is supported.
	 */
	if (hid_data->hkr_dev->irq_mode == IRQ_MODE_MULTI) {
		err = request_irq(hid_data->irq, hkr_hid_irq,
		                  0, HKR_HID_NAME, hid_data);
		if (err) {
			dev_err(hid_data->parent_dev, "request hid irq failed\n");
			goto err_requset_irq;
		}
	}

	err = hid_add_device(hid);
	if (err) {
		dev_err(hid_data->parent_dev, "add HID device failed\n");
		goto err_add_device;
	}

	hid_data->dev = &hid->dev;
	dev_info(hid_data->dev, "hkr-hid device register done\n");

	return 0;

err_add_device:
	free_irq(hid_data->irq, hid_data);
err_requset_irq:
	hkr_hid_free_data_buffers(hid_data);
err_alloc_buff:
	hid_destroy_device(hid);

	return err;
}

void hkr_hid_remove(struct hkr_hid_data *hid_data)
{
	if (hid_data->hid)
		hid_destroy_device(hid_data->hid);

	free_irq(hid_data->irq, hid_data);
	hkr_hid_free_data_buffers(hid_data);
}

MODULE_LICENSE("GPL v2");
