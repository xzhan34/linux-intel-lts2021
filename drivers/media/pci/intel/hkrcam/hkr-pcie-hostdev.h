#ifndef PCIE_HOSTDEV_INTF_H
#define PCIE_HOSTDEV_INTF_H
/* Memory layout */
#define HKR_MAX_BUFFER_NUM 4

#define HKR_MAX_NUM_OF_STREAMS 16
#define HKR_MAX_STREAM_NUM HKR_MAX_NUM_OF_STREAMS
/* When using message buf. We should pay attention to buffer size*/
struct hkr_msg_buf;
#define MSG_ITEM_NUM  (32)
#define MSG_ITEM_SIZE (32) /* each message has 32 bytes */
#define MSG_BUF_SIZE (sizeof(struct hkr_msg_buf))

#define HKR_IMU_MAX_REPORT_SIZE (MSG_BUF_SIZE - 64)

#define HKR_MEM_BAR_BASE (0x00)
#define HKR_HOST_INFO_SIZE (1 << 7)

/* 64bit for Device INIT status */
#define HKR_EP_INT_STAUS_OFF (HKR_MEM_BAR_BASE + 0x00)

#define HKR_DEVICE_INFO_OFF (HKR_MEM_BAR_BASE + 0x80)
#define HKR_DEVICE_CTRL_OFF (HKR_MEM_BAR_BASE + 0x400)
#define HKR_HOST_INFO_OFF (HKR_MEM_BAR_BASE + 0x480)
#define HKR_HOST2DEV_MSG_OFF (HKR_HOST_INFO_OFF + \
				(HKR_HOST_INFO_SIZE * HKR_MAX_STREAM_NUM))
#define HKR_DEV2HOST_MSG_OFF (HKR_HOST2DEV_MSG_OFF + MSG_BUF_SIZE)
#define HKR_RING_DESC_OFF_IN_BAR (HKR_DEV2HOST_MSG_OFF + MSG_BUF_SIZE)

/* HKR global control address */
#define HKR_HOST_STAT_IRQ_INIT_DONE 0x01
#define HKR_HOST_STAT_PROBE_DONE 0x02

#define HKR_REST_DEVICE_BIT 0x01
#define HKR_HOST_DRV_STAT_OFF  (HKR_DEVICE_CTRL_OFF + 0x00)
#define HKR_RST_DEVICE_OFF  (HKR_DEVICE_CTRL_OFF + 0x04)
#define HKR_HOST_MSG_SEND_CMD_OFF (HKR_DEVICE_CTRL_OFF + 0x08)
#define HKR_DEV_MSG_SEND_CMD_OFF (HKR_DEVICE_CTRL_OFF + 0x0c)
#define HKR_RING_DESCS_LOW_OFF  (HKR_DEVICE_CTRL_OFF + 0x20)
#define HKR_RING_DESCS_HIGH_OFF  (HKR_DEVICE_CTRL_OFF + 0x24)
#define HKR_RING_EACH_SIZE_OFF  (HKR_DEVICE_CTRL_OFF + 0x2c)

/*
 * 128 byte for each stream
 * TODO: if each block is not at cache line boundary, and the bar size is
 * not cache off, there will be problem when cache clean/invalidata as it will
 * affect the area of other stream.
 */

#define HKR_STREAM_CRTL_OFF(n) (HKR_HOST_INFO_OFF + \
			(HKR_HOST_INFO_SIZE * n))
#define HKR_CMD_OFF				0x00  /* TODO: move to struct later */
#define HKR_CMD_PARAM_LOW_OFF	0x04
#define HKR_CMD_PARAM_HIGH_OFF	0x08
#define HKR_DMA_DESC_LOW_OFF	0x0C
#define HKR_DMA_DESC_HIGH_OFF	0x10

#define HKR_EEPROM_DATA_OFF (HKR_MEM_BAR_BASE + 0x19000)
#define HKR_SENSOR_EEPROM_SIZE 0x5b
/* End of Memory layout */

/* Define INT status from EP to host */
#define HKR_EP_INT_FRAME(n) (0x01ULL << n) /* n is 0..31 */
#define HKR_EP_INT_MSG (0x01ULL << 40U)

enum {
	HKR_STREAM_CMD_NONE = 0,
	HKR_STREAM_CMD_ONOFF,
	HKR_STREAM_CMD_CFG_BUF,
};

enum {
	HKR_STREAM_OFF = 0,
	HKR_STREAM_ON = 1,
};

enum {
	MBX_PL_TYPE_MSG,
	MBX_PL_TYPE_QUEUE_BUF
};

enum hkr_msg_type {
	/* host lib standard message */
	HKR_MSG_GET_UC_LIST = 1,
	HKR_MSG_GET_UC_LIST_ACK,
	HKR_MSG_GET_UC_CAPS,
	HKR_MSG_GET_UC_CAPS_ACK,
	HKR_MSG_STREAM_OPEN,
	HKR_MSG_STREAM_OPEN_ACK,
	HKR_MSG_STREAM_START,
	HKR_MSG_STREAM_START_ACK,
	HKR_MSG_STREAM_SET_PARAM,
	HKR_MSG_STREAM_SET_PARAM_ACK,
	HKR_MSG_STREAM_STOP,
	HKR_MSG_STREAM_STOP_ACK,
	HKR_MSG_STREAM_CLOSE_ACK,

	/* Stream Specific message */
	HKR_MSG_IMU_GET_DESC,
	HKR_MSG_IMU_GET_DESC_ACK,
	HKR_MSG_IMU_GET_REPORT,
	HKR_MSG_IMU_GET_REPORT_ACK,
	HKR_MSG_IMU_SET_REPORT,
	HKR_MSG_IMU_SET_REPORT_ACK,

	HKR_MSG_N,
};

struct hkr_msg_buf_header
{
	uint64_t msg_num;
	uint64_t item_size;
	uint64_t rd_idx;
	uint64_t wr_idx;
} __attribute__ ((__packed__));

struct hkr_msg_item
{
	uint8_t data[MSG_ITEM_SIZE];
} __attribute__ ((__packed__));

struct hkr_msg_buf
{
	struct hkr_msg_buf_header header;
	struct hkr_msg_item items[MSG_ITEM_NUM];
} __attribute__ ((__packed__));

struct hkr_msg_header {
	uint8_t msg_type;           /**< The type of the message. */
	uint16_t msg_size;          /**< The total size of the message. */
	uint8_t reserved[1];        /**< Reserved for 32 bits alignment. */
} __attribute__ ((__packed__));

struct hkr_msg_ack_header {
	uint8_t msg_type;           /**< The type of the ack message. */
	uint16_t msg_size;          /**< The total size of the ack message. */
	int8_t error_code;          /**< The status of the message. */
} __attribute__ ((__packed__));

struct hkr_msg_start {
	struct hkr_msg_header header;           /**< The header of the massage. */
	uint8_t num_of_stream;                  /**< How many streams need to be started. */
	uint8_t stream_ids[HKR_MAX_NUM_OF_STREAMS]; /**< The actual stream IDs that need to be started. */
	uint8_t reserved[3];                    /**< Reserved for 32 bits alignment. */
} __attribute__ ((__packed__));

struct hkr_msg_start_done {
	struct hkr_msg_ack_header header;  /**< The header of the massage. */
	uint8_t num_of_stream;                  /**< How many streams need to be started. */
	uint8_t stream_ids[HKR_MAX_NUM_OF_STREAMS]; /**< The actual stream IDs that need to be started. */
	uint8_t reserved[3];
} __attribute__ ((__packed__));

/**
 * @brief The message for stop command
 */
struct hkr_msg_stop {
	struct hkr_msg_header header;               /**< The header of the massage. */
	uint8_t num_of_stream;                      /**< How many streams need to be stopped. */
	uint8_t stream_ids[HKR_MAX_NUM_OF_STREAMS]; /**< The actual stream IDs need to be stopped. */
	uint8_t reserved[3];                        /**< Reserved for 32 bits alignment. */
} __attribute__ ((__packed__));

/**
 * @brief The ack message for stop command
 */
struct hkr_msg_stop_done {
	struct hkr_msg_ack_header header;  /**< The header of the massage. */
	uint8_t num_of_stream;                      /**< How many streams need to be stopped. */
	uint8_t stream_ids[HKR_MAX_NUM_OF_STREAMS]; /**< The actual stream IDs need to be stopped. */
	uint8_t reserved[3];
} __attribute__ ((__packed__));

/* IMU related messaage */
struct hkr_msg_imu_get_desc {
	struct hkr_msg_header header;  /**< The header of the massage. */
	uint8_t stream_id;  /* stream id */
} __attribute__ ((__packed__));

struct hkr_msg_imu_get_desc_done {
	struct hkr_msg_ack_header header;  /**< The header of the massage. */
	uint8_t stream_id;
	uint8_t reserved; /**< reserved for align */
	uint16_t desc_size;
	uint8_t desc[HKR_IMU_MAX_REPORT_SIZE];
} __attribute__ ((__packed__));

struct hkr_msg_imu_get_report {
	struct hkr_msg_header header;  /**< The header of the massage. */
	uint8_t stream_id;  /* stream id */
	uint8_t report_id;  /**< report ID */
	uint8_t report_type;  /**< report type: input/output/featur */
	uint8_t reserved;
	uint32_t  count;
} __attribute__ ((__packed__));

struct hkr_msg_imu_get_report_done {
	struct hkr_msg_ack_header header;  /**< The header of the massage. */
	uint8_t stream_id;
	uint8_t reserved; /**< reserved for align */
	uint16_t report_size;
	uint8_t report[HKR_IMU_MAX_REPORT_SIZE];
} __attribute__ ((__packed__));

struct hkr_msg_imu_set_report {
	struct hkr_msg_header header;           /**< The header of the massage. */
	uint8_t stream_id;
	uint8_t report_id;  /**< report ID */
	uint8_t report_type;  /**< report type: input/output/featur */
	uint8_t reserved;  /**< reserved for align */
	uint16_t report_size;
	uint8_t report[HKR_IMU_MAX_REPORT_SIZE];
} __attribute__ ((__packed__));

struct hkr_msg_imu_set_report_done {
	struct hkr_msg_ack_header header;  /**< The header of the massage. */
	uint8_t stream_id;
} __attribute__ ((__packed__));

/* End of IMU related messaage */

/* We must assure bytes align with HKR EP */
struct hkr_ring_desc {
	uint64_t buf_num;
	uint64_t rd_index;
	uint64_t wr_index;
	uint64_t dma_addr[HKR_MAX_BUFFER_NUM];
	uint64_t cpu_addr[HKR_MAX_BUFFER_NUM];
} __attribute__ ((__packed__));

/* Use case ABI */

struct hkr_cfg_info_header {
	uint16_t type;
	uint16_t size;
} __attribute__ ((__packed__));

/*
 * We keep 128 bytes space for endpoint-test. 128 bytes is enough for
 * current usage. Please refer to struct pcie_ep_test_reg.
 * TODO: We will remove this in real product.
 */
struct hkr_image_stream {
	struct hkr_cfg_info_header header;
	uint32_t stream_index;
	uint32_t cam_index; /* the camera this stream binding to */
	uint32_t irq_index;
	uint32_t width;
	uint32_t height;
	uint32_t fourcc;
	uint32_t depth;
} __attribute__ ((__packed__));

struct hkr_meta_stream {
	struct hkr_cfg_info_header header;
	uint32_t stream_index;
	uint32_t cam_index; /* the camera this stream binding to */
	uint32_t irq_index;
	uint32_t size;
} __attribute__ ((__packed__));

struct hkr_imu_stream {
	struct hkr_cfg_info_header header;
	uint32_t stream_index;
	uint32_t dev_index; /* the camera this stream binding to */
	uint32_t irq_index;
	uint32_t size;
} __attribute__ ((__packed__));

struct hkr_device_info {
	uint32_t hw_version;
	uint32_t fw_version;
	uint32_t sw_version;
} __attribute__ ((__packed__));

enum HKR_USECASE_TYPE {
	HKR_USECASE_ALL_CAMERAS = 0,
	HKR_USECASE_DEPTH,
};

enum HKR_STREAM_TYPE {
	HKR_STREAM_IMAGE = 0,
	HKR_STREAM_META,
	HKR_STREAM_IMU,
};

struct hkr_usecase_info {
	struct hkr_cfg_info_header header;
	uint32_t stream_num;
} __attribute__ ((__packed__));

struct hkr_device_config {
	uint32_t usecase_num;
	struct hkr_device_info device_info;
	uint64_t usecase_data[HKR_MAX_STREAM_NUM];
} __attribute__ ((__packed__));

#define MBX_HEADER_VF1          (0xC00)
#define MBX_PAYLOAD0_VF1        (0xC04)
#define MBX_PAYLOAD1_VF1        (0xC08)
#define MBX_PAYLOAD2_VF1        (0xC0C)
#define MBX_PAYLOAD3_VF1        (0xC10)
#define MBX_PAYLOAD4_VF1        (0xC14)
#define MBX_PAYLOAD5_VF1        (0xC18)
#define MBX_PAYLOAD6_VF1        (0xC1C)
#define MBX_PAYLOAD7_VF1        (0xC20)

#define MBX_DEFAULT_HEADER      (0x8234ABCD)
#define MBX_PAYLOAD_READ        (0x12345678)
#define MBX_PAYLOAD_WRITE       (0x23456789)
#define MBX_PAYLOAD_COPY        (0x3456789A)
#define MBX_PAYLOAD_IRQ         (0x456789AB)

struct notify_param {
	uint32_t header;
	uint32_t payload[8];
};

/* End of use case ABI */
#endif
