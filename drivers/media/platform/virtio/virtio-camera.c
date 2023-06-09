// SPDX-License-Identifier: GPL-2.0-or-later
 /*
  * Driver for VirtIO camera device.
  *
  * Copyright © 2022 Collabora, Ltd.
  */

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_camera.h>
#include <linux/virtio_types.h>
#include <linux/virtio_ids.h>
#include <media/videobuf2-dma-sg.h>

#include <media/media-device.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-device.h>
#include <media/v4l2-event.h>
#include <media/v4l2-ioctl.h>

struct virtio_camera_ctrl_req {
	struct virtio_camera_op_ctrl_req ctrl;
	struct virtio_camera_op_ctrl_req resp;
	struct completion completion;
	struct vb2_buffer *vb;
};

struct virtio_camera {
	struct v4l2_device v4l2_dev;
	struct v4l2_m2m_dev *m2m;
	struct media_device mdev;
	struct video_device vdev;
	struct mutex v4l2_lock;
	struct vb2_queue vq;
	struct virtqueue *vqx;
	struct virtio_camera_ctrl_req req;
	struct virtio_camera_config config;
	struct v4l2_format f;
};

struct virtio_camera_buffer {
	struct vb2_v4l2_buffer vb;
	struct virtio_camera_ctrl_req req;
	u8 uuid[16];
};

static const struct v4l2_file_operations vcam_v4l2_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = video_ioctl2,
	.open = v4l2_fh_open,
	.release = vb2_fop_release,
	.poll = vb2_fop_poll,
	.mmap = vb2_fop_mmap,
	.read = vb2_fop_read,
};

static inline struct virtio_camera_buffer *
vb_to_vcam_buf(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);

	return container_of(vbuf, struct virtio_camera_buffer, vb);
}

static void virtio_camera_control_ack(struct virtqueue *vq)
{
	struct virtio_camera_ctrl_req *req;
	unsigned int len;

	while ((req = virtqueue_get_buf(vq, &len))) {
		complete(&req->completion);

		if (req->vb)
			vb2_buffer_done(req->vb, VB2_BUF_STATE_DONE);
	}
}

static void vcam_init_request(struct virtio_camera_ctrl_req *req)
{
	init_completion(&req->completion);
}

static int vcam_vq_request(struct virtio_camera *vcam,
			   struct virtio_camera_ctrl_req *req,
			   struct virtio_camera_mem_entry *ents,
			   unsigned int num_ents,
			   bool async)
{
	struct scatterlist vreq[3], *sgs[3];
	unsigned int num_sgs = 0;
	int ret;

	memset(&req->resp, 0, sizeof(req->resp));

	sg_init_one(&vreq[0], &req->ctrl, sizeof(req->ctrl));
	sgs[num_sgs++] = &vreq[0];

	if (ents) {
		sg_init_one(&vreq[1], ents, sizeof(*ents) * num_ents);
		sgs[num_sgs++] = &vreq[1];
	}

	sg_init_one(&vreq[2], &req->resp, sizeof(req->resp));
	sgs[num_sgs++] = &vreq[2];

	reinit_completion(&req->completion);

	virtqueue_add_sgs(vcam->vqx, sgs, num_sgs - 1, 1, req, GFP_KERNEL);
	virtqueue_kick(vcam->vqx);

	if (async)
		return 0;

	wait_for_completion(&req->completion);

	memset(&req->ctrl, 0, sizeof(req->ctrl));

	switch (req->resp.header.cmd) {
	case VIRTIO_CAMERA_CMD_RESP_OK_NODATA:
		ret = 0;
		break;

	case VIRTIO_CAMERA_CMD_RESP_ERR_BUSY:
		ret = -EBUSY;
		break;

	case VIRTIO_CAMERA_CMD_RESP_ERR_OUT_OF_MEMORY:
		ret = -ENOMEM;
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int vcam_querycap(struct file *file, void *priv,
			 struct v4l2_capability *cap)
{
	struct virtio_camera *vcam = video_drvdata(file);

	strscpy(cap->bus_info, "platform:camera", sizeof(cap->bus_info));
	strscpy(cap->driver, "virtio-camera", sizeof(cap->driver));
	strscpy(cap->card, vcam->config.name, sizeof(cap->card));

	return 0;
}

static int vcam_enum_fmt(struct file *file, void *fh, struct v4l2_fmtdesc *f)
{
	struct virtio_camera *vcam = video_drvdata(file);
	int err;

	vcam->req.ctrl.header.cmd = VIRTIO_CAMERA_CMD_ENUM_FORMAT;
	vcam->req.ctrl.header.index = f->index;

	err = vcam_vq_request(vcam, &vcam->req, NULL, 0, false);
	if (err)
		return err;

	f->pixelformat = vcam->req.resp.u.format.pixelformat;

	return 0;
}

static int vcam_enum_framesizes(struct file *file, void *fh,
				struct v4l2_frmsizeenum *fsize)
{
	struct virtio_camera *vcam = video_drvdata(file);
	struct virtio_camera_format_size *sz = &vcam->req.resp.u.format.size;
	int err;

	vcam->req.ctrl.header.cmd = VIRTIO_CAMERA_CMD_ENUM_SIZE;
	vcam->req.ctrl.header.index = fsize->index;
	vcam->req.ctrl.u.format.pixelformat = fsize->pixel_format;

	err = vcam_vq_request(vcam, &vcam->req, NULL, 0, false);
	if (err)
		return err;

	if (sz->min_width == sz->max_width && sz->min_height == sz->max_height) {
		fsize->discrete.width = sz->width;
		fsize->discrete.height = sz->height;
		fsize->type = V4L2_FRMSIZE_TYPE_DISCRETE;
	} else {
		fsize->stepwise.min_width = sz->min_width;
		fsize->stepwise.max_width = sz->max_width;
		fsize->stepwise.min_height = sz->min_height;
		fsize->stepwise.max_height = sz->max_height;
		fsize->stepwise.step_width = sz->step_width;
		fsize->stepwise.step_height = sz->max_height;

		if (sz->step_width == 1 && sz->step_height == 1)
			fsize->type = V4L2_FRMSIZE_TYPE_CONTINUOUS;
		else
			fsize->type = V4L2_FRMSIZE_TYPE_STEPWISE;
	}

	return 0;
}

static int vcam_g_fmt(struct file *file, void *fh, struct v4l2_format *f)
{
	struct virtio_camera *vcam = video_drvdata(file);
	int err;

	vcam->req.ctrl.header.cmd = VIRTIO_CAMERA_CMD_GET_FORMAT;

	err = vcam_vq_request(vcam, &vcam->req, NULL, 0, false);
	if (err)
		return err;

	f->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

	f->fmt.pix.flags = 0;
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.width = vcam->req.resp.u.format.size.width;
	f->fmt.pix.height = vcam->req.resp.u.format.size.height;
	f->fmt.pix.pixelformat = vcam->req.resp.u.format.pixelformat;
	f->fmt.pix.bytesperline = vcam->req.resp.u.format.size.stride;
	f->fmt.pix.sizeimage = vcam->req.resp.u.format.size.sizeimage;

	/* TODO */
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.colorspace = V4L2_COLORSPACE_SRGB;

	return 0;
}

static int vcam_s_fmt(struct file *file, void *fh, struct v4l2_format *f)
{
	struct virtio_camera *vcam = video_drvdata(file);
	int err;

	if (f->type != V4L2_BUF_TYPE_VIDEO_CAPTURE)
		return -EINVAL;

	vcam->req.ctrl.header.cmd = VIRTIO_CAMERA_CMD_SET_FORMAT;
	vcam->req.ctrl.u.format.size.width = f->fmt.pix.width;
	vcam->req.ctrl.u.format.size.height = f->fmt.pix.height;
	vcam->req.ctrl.u.format.size.stride = f->fmt.pix.bytesperline;
	vcam->req.ctrl.u.format.pixelformat = f->fmt.pix.pixelformat;

	err = vcam_vq_request(vcam, &vcam->req, NULL, 0, false);
	if (err)
		return err;

	f->fmt.pix.flags = 0;
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.width = vcam->req.resp.u.format.size.width;
	f->fmt.pix.height = vcam->req.resp.u.format.size.height;
	f->fmt.pix.pixelformat = vcam->req.resp.u.format.pixelformat;
	f->fmt.pix.bytesperline = vcam->req.resp.u.format.size.stride;
	f->fmt.pix.sizeimage = vcam->req.resp.u.format.size.sizeimage;

	/* TODO */
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.colorspace = V4L2_COLORSPACE_SRGB;

	vcam->f = *f;

	return err;
}

static int vcam_try_fmt(struct file *file, void *fh, struct v4l2_format *f)
{
	struct virtio_camera *vcam = video_drvdata(file);
	int err;

	vcam->req.ctrl.header.cmd = VIRTIO_CAMERA_CMD_TRY_FORMAT;
	vcam->req.ctrl.u.format.size.width = f->fmt.pix.width;
	vcam->req.ctrl.u.format.size.height = f->fmt.pix.height;
	vcam->req.ctrl.u.format.size.stride = f->fmt.pix.bytesperline;
	vcam->req.ctrl.u.format.pixelformat = f->fmt.pix.pixelformat;

	err = vcam_vq_request(vcam, &vcam->req, NULL, 0, false);
	if (err)
		return err;

	f->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

	f->fmt.pix.flags = 0;
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.width = vcam->req.resp.u.format.size.width;
	f->fmt.pix.height = vcam->req.resp.u.format.size.height;
	f->fmt.pix.pixelformat = vcam->req.resp.u.format.pixelformat;
	f->fmt.pix.bytesperline = vcam->req.resp.u.format.size.stride;
	f->fmt.pix.sizeimage = vcam->req.resp.u.format.size.sizeimage;

	/* TODO */
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.colorspace = V4L2_COLORSPACE_SRGB;

	return 0;
}

static int vcam_enum_input(struct file *filp, void *p,
			   struct v4l2_input *input)
{
	if (input->index > 0)
		return -EINVAL;

	strscpy(input->name, "virtio-camera0", sizeof(input->name));
	input->type = V4L2_INPUT_TYPE_CAMERA;
	input->std = V4L2_STD_UNKNOWN;
	input->status = 0;

	return 0;
}

static int vcam_g_input(struct file *filp, void *p, unsigned int *i)
{
	*i = 0;

	return 0;
}

static int vcam_s_input(struct file *filp, void *p, unsigned int i)
{
	if (i)
		return -EINVAL;

	return 0;
}

static const struct v4l2_ioctl_ops vcam_ioctl_ops = {
	.vidioc_querycap = vcam_querycap,
	.vidioc_enum_fmt_vid_cap = vcam_enum_fmt,
	.vidioc_enum_framesizes = vcam_enum_framesizes,
	.vidioc_g_fmt_vid_cap = vcam_g_fmt,
	.vidioc_s_fmt_vid_cap = vcam_s_fmt,
	.vidioc_try_fmt_vid_cap = vcam_try_fmt,
	.vidioc_reqbufs = vb2_ioctl_reqbufs,
	.vidioc_querybuf = vb2_ioctl_querybuf,
	.vidioc_qbuf = vb2_ioctl_qbuf,
	.vidioc_expbuf = vb2_ioctl_expbuf,
	.vidioc_dqbuf = vb2_ioctl_dqbuf,
	.vidioc_create_bufs = vb2_ioctl_create_bufs,
	.vidioc_prepare_buf = vb2_ioctl_prepare_buf,
	.vidioc_streamon = vb2_ioctl_streamon,
	.vidioc_streamoff = vb2_ioctl_streamoff,
	.vidioc_enum_input = vcam_enum_input,
	.vidioc_g_input = vcam_g_input,
	.vidioc_s_input = vcam_s_input,
};

static int
vcam_queue_setup(struct vb2_queue *vq,
		 unsigned int *nbuffers, unsigned int *num_planes,
		 unsigned int sizes[], struct device *alloc_devs[])

{
	struct virtio_camera *vcam = vb2_get_drv_priv(vq);
	unsigned int size = vcam->f.fmt.pix.sizeimage;
	int ret;

	if (vq->num_buffers + *nbuffers < 2)
		*nbuffers = 2 - vq->num_buffers;

	if (*num_planes) {
		ret = sizes[0] < size ? -EINVAL : 0;
		return ret;
	}

	*num_planes = 1;
	sizes[0] = size;

	return 0;
}

static int vcam_buf_init(struct vb2_buffer *vb)
{
	struct virtio_camera *vcam = vb2_get_drv_priv(vb->vb2_queue);
	struct virtio_camera_buffer *vbuf = vb_to_vcam_buf(vb);
	struct virtio_camera_mem_entry *ents;
	struct scatterlist *sg;
	struct sg_table *sgt;
	unsigned int i;
	int err;

	/* TODO */
	if (WARN_ON(vb->num_planes != 1))
		return -EINVAL;

	sgt = vb2_dma_sg_plane_desc(vb, 0);
	ents = kmalloc_array(sgt->nents, sizeof(*ents), GFP_KERNEL);
	if (!ents)
		return -ENOMEM;

	for_each_sg(sgt->sgl, sg, sgt->nents, i) {
		ents[i].addr = cpu_to_le64(sg_phys(sg));
		ents[i].length = cpu_to_le32(sg->length);
	}

	vcam->req.ctrl.header.cmd = VIRTIO_CAMERA_CMD_CREATE_BUFFER;
	vcam->req.ctrl.u.buffer.num_entries = sgt->nents;

	err = vcam_vq_request(vcam, &vcam->req, ents, sgt->nents, false);
	kfree(ents);
	if (err)
		return err;

	memcpy(vbuf->uuid, vcam->req.resp.u.buffer.uuid, sizeof(vbuf->uuid));

	vcam_init_request(&vbuf->req);
	vbuf->req.vb = vb;

	return 0;
}

static void vcam_buf_cleanup(struct vb2_buffer *vb)
{
	struct virtio_camera *vcam = vb2_get_drv_priv(vb->vb2_queue);
	struct virtio_camera_buffer *vbuf = vb_to_vcam_buf(vb);

	vcam->req.ctrl.header.cmd = VIRTIO_CAMERA_CMD_DESTROY_BUFFER;
	memcpy(vcam->req.ctrl.u.buffer.uuid, vbuf->uuid, sizeof(vbuf->uuid));

	vcam_vq_request(vcam, &vcam->req, NULL, 0, false);
}

static int vcam_buf_prepare(struct vb2_buffer *vb)
{
	struct virtio_camera *vcam = vb2_get_drv_priv(vb->vb2_queue);

	vb2_set_plane_payload(vb, 0, vcam->f.fmt.pix.sizeimage);

	return 0;
}

static void vcam_buf_queue(struct vb2_buffer *vb)
{
	struct virtio_camera *vcam = vb2_get_drv_priv(vb->vb2_queue);
	struct virtio_camera_buffer *vbuf = vb_to_vcam_buf(vb);
	int err;

	vbuf->req.ctrl.header.cmd = VIRTIO_CAMERA_CMD_ENQUEUE_BUFFER;
	memcpy(vbuf->req.ctrl.u.buffer.uuid, vbuf->uuid, sizeof(vbuf->uuid));

	err = vcam_vq_request(vcam, &vbuf->req, NULL, 0, true);
	if (err)
		vb2_buffer_done(vb, VB2_BUF_STATE_ERROR);
}

static int vcam_start_streaming(struct vb2_queue *q, unsigned int count)
{
	struct virtio_camera *vcam = vb2_get_drv_priv(q);
	int err;

	vcam->req.ctrl.header.cmd = VIRTIO_CAMERA_CMD_STREAM_ON;

	err = vcam_vq_request(vcam, &vcam->req, NULL, 0, false);
	if (err)
		return err;

	return 0;
}

static void vcam_stop_streaming(struct vb2_queue *q)
{
	struct virtio_camera *vcam = vb2_get_drv_priv(q);

	vcam->req.ctrl.header.cmd = VIRTIO_CAMERA_CMD_STREAM_OFF;

	vcam_vq_request(vcam, &vcam->req, NULL, 0, false);

	vb2_wait_for_all_buffers(q);
}

static const struct vb2_ops vcam_vb2_ops = {
	.queue_setup = vcam_queue_setup,
	.wait_prepare = vb2_ops_wait_prepare,
	.wait_finish = vb2_ops_wait_finish,
	.buf_init = vcam_buf_init,
	.buf_queue = vcam_buf_queue,
	.buf_cleanup = vcam_buf_cleanup,
	.buf_prepare = vcam_buf_prepare,
	.start_streaming = vcam_start_streaming,
	.stop_streaming = vcam_stop_streaming,
};

static void delete_vqs(void *data)
{
	struct virtio_device *vdev = data;

	vdev->config->del_vqs(vdev);
}

static int virtio_camera_probe(struct virtio_device *vdev)
{
	static vq_callback_t *callbacks[] = { virtio_camera_control_ack };
	static const char * const names[] = { "control" };
	struct virtio_camera *vcam;
	struct virtqueue *vqs[1];
	int err;

	vcam = devm_kzalloc(&vdev->dev, sizeof(*vcam), GFP_KERNEL);
	if (!vcam)
		return -ENOMEM;

	vdev->priv = vcam;
	mutex_init(&vcam->v4l2_lock);
	vcam_init_request(&vcam->req);
	media_device_init(&vcam->mdev);
	video_set_drvdata(&vcam->vdev, vcam);

	vcam->vdev.queue = &vcam->vq;
	vcam->vdev.lock = &vcam->v4l2_lock,
	vcam->vdev.fops = &vcam_v4l2_fops,
	vcam->vdev.vfl_dir = VFL_DIR_RX,
	vcam->vdev.release = video_device_release_empty,
	vcam->vdev.v4l2_dev = &vcam->v4l2_dev;
	vcam->vdev.ioctl_ops = &vcam_ioctl_ops,
	vcam->vdev.device_caps = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING;

	vcam->vq.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	vcam->vq.buf_struct_size = sizeof(struct virtio_camera_buffer);
	vcam->vq.timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
	vcam->vq.io_modes = VB2_MMAP | VB2_DMABUF;
	vcam->vq.mem_ops = &vb2_dma_sg_memops;
	vcam->vq.lock = &vcam->v4l2_lock;
	vcam->vq.min_buffers_needed = 1;
	vcam->vq.gfp_flags = GFP_DMA32;
	vcam->vq.ops = &vcam_vb2_ops;
	vcam->vq.dev = vdev->dev.parent;
	vcam->vq.drv_priv = vcam;

	err = virtio_find_vqs(vdev, 1, vqs, callbacks, names, NULL);
	if (err)
		return dev_err_probe(&vdev->dev, err,
				     "failed to find virt queue\n");

	err = devm_add_action_or_reset(&vdev->dev, delete_vqs, vdev);
	if (err)
		return err;

	vcam->vqx = vqs[0];

	virtio_cread_bytes(vdev, 0, &vcam->config, sizeof(vcam->config));

	err = vb2_queue_init(&vcam->vq);
	if (err)
		return dev_err_probe(&vdev->dev, err,
				     "failed to initialize vb2 queue\n");

	err = v4l2_device_register(&vdev->dev, &vcam->v4l2_dev);
	if (err)
		return dev_err_probe(&vdev->dev, err,
				     "failed to register v4l2 device\n");

	err = video_register_device(&vcam->vdev, VFL_TYPE_VIDEO, -1);
	if (err) {
		v4l2_device_unregister(&vcam->v4l2_dev);
		return dev_err_probe(&vdev->dev, err,
				     "failed to register video device\n");
	}

	return 0;
}

static void virtio_camera_remove(struct virtio_device *vdev)
{
	struct virtio_camera *vcam = vdev->priv;

	video_unregister_device(&vcam->vdev);
	v4l2_device_unregister(&vcam->v4l2_dev);
	virtio_break_device(vdev);
	vdev->config->reset(vdev);

}

static const unsigned int features[] = {
	/* none */
};

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_CAMERA, VIRTIO_DEV_ANY_ID },
	{},
};
MODULE_DEVICE_TABLE(virtio, id_table);

static struct virtio_driver virtio_camera_driver = {
	.feature_table_size = ARRAY_SIZE(features),
	.feature_table = features,
	.probe = virtio_camera_probe,
	.remove = virtio_camera_remove,
	.driver.name = "virtio-camera",
	.id_table = id_table,
};
module_virtio_driver(virtio_camera_driver);

MODULE_AUTHOR("Dmitry Osipenko <dmitry.osipenko@collabora.com>");
MODULE_DESCRIPTION("virtio camera device driver");
MODULE_LICENSE("GPL");
