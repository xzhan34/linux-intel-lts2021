#ifndef _HKR_MOC_DRV_H_
#define _HKR_MOC_DRV_H_

struct hkr_hid_desc {
	__le16 wHIDDescLength;
	__le16 bcdVersion;
	__le16 wReportDescLength;
	__le16 wReportDescRegister;
	__le16 wInputRegister;
	__le16 wMaxInputLength;
	__le16 wOutputRegister;
	__le16 wMaxOutputLength;
	__le16 wCommandRegister;
	__le16 wDataRegister;
	__le16 wVendorID;
	__le16 wProductID;
	__le16 wVersionID;
	__le32 reserved;
} __packed;

struct hid_device;

/* The main device structure */
struct hkr_hid_data {
	uint8_t stream_id;
	int irq;
	int buf_size;
	struct device *dev;
	struct device *parent_dev;
	struct hkr_device *hkr_dev;
	struct hid_device	*hid;	/* pointer to corresponding HID dev */
	void __iomem *base;
	void *ring_cpu_addr;
	dma_addr_t ring_bus_addr;	/* ring desc DMA addr aligned*/
	struct hkr_ring_desc *ring; /* ring desc CPU addr aligned */
};

int hkr_create_hid_device(struct hkr_hid_data *hid_data);
void hkr_hid_remove(struct hkr_hid_data *hid_data);
irqreturn_t hkr_hid_irq(int irq, void *data);

#endif

