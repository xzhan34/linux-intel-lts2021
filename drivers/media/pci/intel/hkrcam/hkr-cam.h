#ifndef __MEDIA_HKR_CAM_H__
#define __MEDIA_HKR_CAM_H__

/* maximum stream supported, including image/metadata, etc. */
#define HKR_DEV_NAME_LENGTH 32

/* TODO: Needs to confirm from Hardware */
#define HKR_DMA_MASK DMA_BIT_MASK(64)

enum hkr_irq_mod {
	IRQ_MODE_SINGLE,
	IRQ_MODE_MULTI
};

struct hkr_pcie_device_info {
	char name[HKR_DEV_NAME_LENGTH + 1];
	u32 host_drv_version;
	u32 esw_version;
	u32 fw_version;
	u32 hw_version;
};

struct hkr_v4l2_queue {
	/* mutex to be used by vb2_queue */
	int stream_index;

	struct mutex lock;
	struct media_pipeline pipe;
	struct v4l2_subdev *sensor;
	struct v4l2_mbus_framefmt fmt;

	int irq;
	/* PCIE register base for this queue */
	void __iomem *base;

	/* Video device, /dev/videoX */
	struct video_device vdev;
	struct media_pad vdev_pad;
	struct v4l2_pix_format format;
	struct vb2_queue vbq;

	struct completion msg_ack_comp; /* ack completion from client */

	/* Buffer queue handling */
	void *ring_cpu_addr;
	dma_addr_t ring_bus_addr;	/* ring desc DMA addr aligned*/
	struct hkr_ring_desc *ring; /* ring desc CPU addr aligned */
	struct hkr_buffer *bufs[HKR_MAX_BUFFER_NUM];
	unsigned int enq_index;	/* enqueue index */
	unsigned int deq_index;	/* dequeue (buffer done) index */
	atomic_t bufs_queued;
};

struct hkr_buffer {
	struct vb2_v4l2_buffer vbb;
	/* TODO: add more member here */
};

struct hkr_stream_item {
	void *stream;
	struct list_head list;
};

struct hkr_control_dev {
	int major;
	dev_t devid;
	struct cdev cdev;
	struct device *dev;
	struct class *class;
};

/* TODO: move imu, meta, image information to separate structure */
struct hkr_device {
	struct hkr_pcie_device_info dev_info;
	int irq;
	int irq_nums;
	enum hkr_irq_mod irq_mode; /* multi or single irq */
	int stream_nums; /* total number of image, meta and imu streams */
	int image_stream_num; /* number of image streams */
	int meta_stream_num; /* number of meta data streams */
	int imu_stream_num; /* number of imu streams */
	size_t alignment;
	/* TODO: If each device is independent, should we use multiple lock? */
	struct mutex lock;
	struct v4l2_device v4l2_dev;
	void *base;
	struct pci_dev *pdev;
	struct device *dev;
	struct hkr_control_dev ctl_dev;
	struct list_head image_streams;
	struct list_head meta_streams;
	struct list_head imu_streams;
	enum HKR_STREAM_TYPE stream_type[HKR_MAX_STREAM_NUM];
	struct hkr_v4l2_queue queue[HKR_MAX_STREAM_NUM];
	struct hkr_hid_data hid_data[HKR_MAX_STREAM_NUM];
	size_t ring_org_size;
	int  each_ring_size; /* we use same size for each ring */
	void *ring_cpu_org; /* ring desc CPU addr unalign */
	void *ring_cpu_addr;
	dma_addr_t ring_bus_org; /* ring desc DMA addr unalign */
	dma_addr_t ring_bus_addr; /* ring desc DMA addr aligned*/
	struct hkr_msg_buf *msg_buf;
	struct mutex msg_lock;
};

struct hkr_pci_drv_data {
	size_t alignment;
};

static inline struct hkr_v4l2_queue *file_to_hkr_v4l2_queue(struct file *file)
{
	return container_of(video_devdata(file), struct hkr_v4l2_queue, vdev);
}

static inline struct hkr_v4l2_queue *vb2q_to_hkr_v4l2_queue(
        struct vb2_queue *vq)
{
	return container_of(vq, struct hkr_v4l2_queue, vbq);
}

int hkr_send_msg_and_wait_ack(struct hkr_device *hkr_dev,
                              struct hkr_msg_header *snd_header,
                              struct hkr_msg_ack_header *ack_header);
#endif

