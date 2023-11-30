// SPDX-License-Identifier: GPL-2.0-only
/*
 * PCI glue for ISHTP provider device (ISH) driver
 *
 * Copyright (c) 2014-2016, Intel Corporation.
 */

#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/suspend.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/pm_runtime.h>
#define CREATE_TRACE_POINTS
#include <trace/events/intel_ish.h>
#include "ishtp-dev.h"
#include "hw-ish.h"

static const struct pci_device_id ish_pci_tbl[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, CHV_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, BXT_Ax_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, BXT_Bx_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, APL_Ax_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, SPT_Ax_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, CNL_Ax_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, GLK_Ax_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, CNL_H_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, ICL_MOBILE_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, SPT_H_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, CML_LP_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, CMP_H_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, EHL_Ax_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, TGL_LP_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, TGL_H_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, ADL_S_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, ADL_P_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, ADL_N_DEVICE_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, RPL_S_DEVICE_ID)},
	{0, }
};
MODULE_DEVICE_TABLE(pci, ish_pci_tbl);

/**
 * ish_event_tracer() - Callback function to dump trace messages
 * @dev:	ishtp device
 * @format:	printf style format
 *
 * Callback to direct log messages to Linux trace buffers
 */
static __printf(2, 3)
void ish_event_tracer(struct ishtp_device *dev, const char *format, ...)
{
	if (trace_ishtp_dump_enabled()) {
		va_list args;
		char tmp_buf[100];

		va_start(args, format);
		vsnprintf(tmp_buf, sizeof(tmp_buf), format, args);
		va_end(args);

		trace_ishtp_dump(tmp_buf);
	}
}

/**
 * ish_init() - Init function
 * @dev:	ishtp device
 *
 * This function initialize wait queues for suspend/resume and call
 * calls hadware initialization function. This will initiate
 * startup sequence
 *
 * Return: 0 for success or error code for failure
 */
static int ish_init(struct ishtp_device *dev)
{
	int ret;

	/* Set the state of ISH HW to start */
	ret = ish_hw_start(dev);
	if (ret) {
		dev_err(dev->devc, "ISH: hw start failed.\n");
		return ret;
	}

	/* Start the inter process communication to ISH processor */
	ret = ishtp_start(dev);
	if (ret) {
		dev_err(dev->devc, "ISHTP: Protocol init failed.\n");
		return ret;
	}

	return 0;
}

static const struct pci_device_id ish_invalid_pci_ids[] = {
	/* Mehlow platform special pci ids */
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, 0xA309)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, 0xA30A)},
	{}
};

static inline bool ish_should_enter_d0i3(struct pci_dev *pdev)
{
	return !pm_suspend_via_firmware() || pdev->device == CHV_DEVICE_ID;
}

static inline bool ish_should_leave_d0i3(struct pci_dev *pdev)
{
	return !pm_resume_via_firmware() || pdev->device == CHV_DEVICE_ID;
}

static int enable_gpe(struct device *dev)
{
#ifdef CONFIG_ACPI
	acpi_status acpi_sts;
	struct acpi_device *adev;
	struct acpi_device_wakeup *wakeup;

	adev = ACPI_COMPANION(dev);
	if (!adev) {
		dev_err(dev, "get acpi handle failed\n");
		return -ENODEV;
	}
	wakeup = &adev->wakeup;

	/*
	 * Call acpi_disable_gpe(), so that reference count
	 * gpe_event_info->runtime_count doesn't overflow.
	 * When gpe_event_info->runtime_count = 0, the call
	 * to acpi_disable_gpe() simply return.
	 */
	acpi_disable_gpe(wakeup->gpe_device, wakeup->gpe_number);

	acpi_sts = acpi_enable_gpe(wakeup->gpe_device, wakeup->gpe_number);
	if (ACPI_FAILURE(acpi_sts)) {
		dev_err(dev, "enable ose_gpe failed\n");
		return -EIO;
	}

	return 0;
#else
	return -ENODEV;
#endif
}

static void enable_pme_wake(struct pci_dev *pdev)
{
	if ((pci_pme_capable(pdev, PCI_D0) ||
	     pci_pme_capable(pdev, PCI_D3hot) ||
	     pci_pme_capable(pdev, PCI_D3cold)) && !enable_gpe(&pdev->dev)) {
		pci_pme_active(pdev, true);
		dev_dbg(&pdev->dev, "ish ipc driver pme wake enabled\n");
	}
}

static void time_sync_work_fn(struct work_struct *work)
{
	struct ishtp_device *ishtp_dev;

	ishtp_dev = container_of(work, struct ishtp_device, time_sync_work.work);

	pm_runtime_get_sync(ishtp_dev->devc);
	pm_runtime_mark_last_busy(ishtp_dev->devc);
	ish_send_time_sync(ishtp_dev);

	pm_runtime_put_autosuspend(ishtp_dev->devc);

	if (ishtp_dev->time_sync_period)
		schedule_delayed_work(&ishtp_dev->time_sync_work, ishtp_dev->time_sync_period * HZ);
}

static ssize_t time_sync_period_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct ishtp_device *ishtp_dev = pci_get_drvdata(pdev);
	unsigned long val = 0;
	int ret;
	int time_sync_period_pre = ishtp_dev->time_sync_period;

	ret = kstrtoul(buf, 0, &val);
	if (ret)
		return ret;

	if (val > ISHTP_SYNC_PERIOD_MAX)
		return -EINVAL;

	ishtp_dev->time_sync_period = val;

	if (!time_sync_period_pre && ishtp_dev->time_sync_period)
		schedule_delayed_work(&ishtp_dev->time_sync_work, 0);

	return count;
}

static ssize_t time_sync_period_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct ishtp_device *ishtp_dev = pci_get_drvdata(pdev);

	return sysfs_emit(buf, "%ld\n", ishtp_dev->time_sync_period);
}
static DEVICE_ATTR_RW(time_sync_period);

/**
 * ish_probe() - PCI driver probe callback
 * @pdev:	pci device
 * @ent:	pci device id
 *
 * Initialize PCI function, setup interrupt and call for ISH initialization
 *
 * Return: 0 for success or error code for failure
 */
static int ish_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int ret;
	struct ish_hw *hw;
	unsigned long irq_flag = 0;
	struct ishtp_device *ishtp;
	struct device *dev = &pdev->dev;

	/* Check for invalid platforms for ISH support */
	if (pci_dev_present(ish_invalid_pci_ids))
		return -ENODEV;

	/* enable pci dev */
	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(dev, "ISH: Failed to enable PCI device\n");
		return ret;
	}

	/* set PCI host mastering */
	pci_set_master(pdev);

	/* pci request regions for ISH driver */
	ret = pcim_iomap_regions(pdev, 1 << 0, KBUILD_MODNAME);
	if (ret) {
		dev_err(dev, "ISH: Failed to get PCI regions\n");
		return ret;
	}

	/* allocates and initializes the ISH dev structure */
	ishtp = ish_dev_init(pdev);
	if (!ishtp) {
		ret = -ENOMEM;
		return ret;
	}
	hw = to_ish_hw(ishtp);
	ishtp->print_log = ish_event_tracer;

	/* mapping IO device memory */
	hw->mem_addr = pcim_iomap_table(pdev)[0];
	ishtp->pdev = pdev;

	/* request and enable interrupt */
	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES);
	if (!pdev->msi_enabled && !pdev->msix_enabled)
		irq_flag = IRQF_SHARED;

	ret = devm_request_irq(dev, pdev->irq, ish_irq_handler,
			       irq_flag, KBUILD_MODNAME, ishtp);
	if (ret) {
		dev_err(dev, "ISH: request IRQ %d failed\n", pdev->irq);
		return ret;
	}

	dev_set_drvdata(ishtp->devc, ishtp);

	init_waitqueue_head(&ishtp->suspend_wait);
	init_waitqueue_head(&ishtp->resume_wait);
	init_waitqueue_head(&ishtp->d0_wait);
	init_waitqueue_head(&ishtp->rtd3_wait);
	ishtp->suspend_to_d0i3 = false;

	/* Enable PME for EHL */
	if (pdev->device == EHL_Ax_DEVICE_ID) {
		pci_d3cold_disable(pdev);
		device_init_wakeup(dev, true);
		enable_pme_wake(pdev);
	}

	ret = ish_init(ishtp);
	if (ret)
		return ret;

	/* enable runtime pm for EHL */
	if (pdev->device == EHL_Ax_DEVICE_ID) {
		pm_runtime_use_autosuspend(dev);
		pm_runtime_set_autosuspend_delay(dev, 5000);
		pm_runtime_allow(dev);
		pm_runtime_mark_last_busy(dev);
		pm_runtime_put_autosuspend(dev);

		/* start a timmer to sync time with FW for EHL */
		ishtp->time_sync_period = 0;
		device_create_file(dev, &dev_attr_time_sync_period);
		INIT_DELAYED_WORK(&ishtp->time_sync_work, time_sync_work_fn);
	}

	return 0;
}

/**
 * ish_remove() - PCI driver remove callback
 * @pdev:	pci device
 *
 * This function does cleanup of ISH on pci remove callback
 */
static void ish_remove(struct pci_dev *pdev)
{
	struct ishtp_device *ishtp_dev = pci_get_drvdata(pdev);

	if (pdev->device == EHL_Ax_DEVICE_ID) {
		device_remove_file(&pdev->dev, &dev_attr_time_sync_period);
		cancel_delayed_work_sync(&ishtp_dev->time_sync_work);
	}
	ishtp_bus_remove_all_clients(ishtp_dev, false);
	ish_device_disable(ishtp_dev);

	pm_runtime_forbid(&pdev->dev);
}

static struct device __maybe_unused *ish_resume_device;

/* 50ms to get resume response */
#define WAIT_FOR_RESUME_ACK_MS		50

/**
 * ish_resume_handler() - Work function to complete resume
 * @work:	work struct
 *
 * The resume work function to complete resume function asynchronously.
 * There are two resume paths, one where ISH is not powered off,
 * in that case a simple resume message is enough, others we need
 * a reset sequence.
 */
static void __maybe_unused ish_resume_handler(struct work_struct *work)
{
	struct pci_dev *pdev = to_pci_dev(ish_resume_device);
	struct ishtp_device *dev = pci_get_drvdata(pdev);
	uint32_t fwsts = dev->ops->get_fw_status(dev);

	if (dev->suspend_to_d0i3) {
		if (device_may_wakeup(&pdev->dev))
			disable_irq_wake(pdev->irq);

		ish_set_host_ready(dev);

		/* Send D0 notify to call fw back */
		if (dev->pdev->device == EHL_Ax_DEVICE_ID)
			ish_notify_d0(dev);

		if (IPC_IS_ISH_ILUP(fwsts)) {
			ishtp_send_resume(dev);

			/* Waiting to get resume response */
			if (dev->resume_flag)
				wait_event_interruptible_timeout(dev->resume_wait,
					!dev->resume_flag,
					msecs_to_jiffies(WAIT_FOR_RESUME_ACK_MS));
		}

		/*
		 * If the flag is not cleared, something is wrong with ISH FW.
		 * So on resume, need to go through init sequence again.
		 */
		if (dev->resume_flag)
			ish_init(dev);
	} else {
		/*
		 * Resume from the D3, full reboot of ISH processor will happen,
		 * so need to go through init sequence again.
		 */
		ish_init(dev);
	}

	if (pdev->device == EHL_Ax_DEVICE_ID && dev->time_sync_period)
		schedule_delayed_work(&dev->time_sync_work, 0);
}

/**
 * ish_suspend() - ISH suspend callback
 * @device:	device pointer
 *
 * ISH suspend callback
 *
 * Return: 0 to the pm core
 */
static int __maybe_unused ish_suspend(struct device *device)
{
	struct pci_dev *pdev = to_pci_dev(device);
	struct ishtp_device *dev = pci_get_drvdata(pdev);

	if (pdev->device == EHL_Ax_DEVICE_ID)
		cancel_delayed_work_sync(&dev->time_sync_work);

	if (dev->suspend_to_d0i3) {
		/*
		 * If previous suspend hasn't been asnwered then ISH is likely
		 * dead, don't attempt nested notification
		 */
		if (dev->suspend_flag)
			return	0;

		dev->resume_flag = 0;
		dev->suspend_flag = 1;
		ishtp_send_suspend(dev);

		/* 25 ms should be enough for live ISH to flush all IPC buf */
		if (dev->suspend_flag)
			wait_event_interruptible_timeout(dev->suspend_wait,
					!dev->suspend_flag,
					msecs_to_jiffies(25));

		if (dev->suspend_flag) {
			/*
			 * It looks like FW halt, clear the DMA bit, and put
			 * ISH into D3, and FW would reset on resume.
			 */
			ish_disable_dma(dev);
		} else {
			/*
			 * Save state so PCI core will keep the device at D0,
			 * the ISH would enter D0i3
			 */
			if (dev->pdev->device != EHL_Ax_DEVICE_ID)
				pci_save_state(pdev);
			else {
				/* For no Sx suspend case, need send RTD3 notify to keep
				 * wake capability */
				int ret = ish_notify_rtd3(dev);
				if (ret)
					return ret;

				pci_wake_from_d3(pdev, true);
			}

			if (device_may_wakeup(&pdev->dev))
				enable_irq_wake(pdev->irq);
		}
	} else {
		/*
		 * Clear the DMA bit before putting ISH into D3,
		 * or ISH FW would reset automatically.
		 */
		ish_disable_dma(dev);
	}

	return 0;
}

static __maybe_unused DECLARE_WORK(resume_work, ish_resume_handler);
/**
 * ish_resume() - ISH resume callback
 * @device:	device pointer
 *
 * ISH resume callback
 *
 * Return: 0 to the pm core
 */
static int __maybe_unused ish_resume(struct device *device)
{
	struct pci_dev *pdev = to_pci_dev(device);
	struct ishtp_device *dev = pci_get_drvdata(pdev);

	/* add this to finish power flow for EHL */
	if (dev->pdev->device == EHL_Ax_DEVICE_ID) {
		pci_set_power_state(pdev, PCI_D0);
		enable_pme_wake(pdev);
		dev_dbg(dev->devc, "set power state to D0 for ehl\n");
	}

	ish_resume_device = device;
	dev->resume_flag = 1;

	schedule_work(&resume_work);

	return 0;
}


static int __maybe_unused ish_pm_suspend(struct device *device)
{
	struct pci_dev *pdev = to_pci_dev(device);
	struct ishtp_device *dev = pci_get_drvdata(pdev);

	if (ish_should_enter_d0i3(pdev))
		dev->suspend_to_d0i3 = true;
	else
		dev->suspend_to_d0i3 = false;

	return ish_suspend(device);
}

static int __maybe_unused ish_pm_resume(struct device *device)
{
	return ish_resume(device);
}

static int __maybe_unused ish_pm_freeze(struct device *device)
{
	struct pci_dev *pdev = to_pci_dev(device);
	struct ishtp_device *dev = pci_get_drvdata(pdev);

	dev->suspend_to_d0i3 = false;

	return ish_suspend(device);
}

static int __maybe_unused ish_pm_thaw(struct device *device)
{
	return ish_resume(device);
}

static int __maybe_unused ish_pm_poweroff(struct device *device)
{
	struct pci_dev *pdev = to_pci_dev(device);
	struct ishtp_device *dev = pci_get_drvdata(pdev);

	dev->suspend_to_d0i3 = false;

	return ish_suspend(device);
}

static int __maybe_unused ish_pm_restore(struct device *device)
{
	return ish_resume(device);
}

static int __maybe_unused ish_runtime_suspend(struct device *device)
{
	struct pci_dev *pdev = to_pci_dev(device);
	struct ishtp_device *dev = pci_get_drvdata(pdev);
	int ret = 0;

	if (dev->pdev->device == EHL_Ax_DEVICE_ID)
		ret = ish_notify_rtd3(dev);

	return ret;
}

static int __maybe_unused ish_runtime_resume(struct device *device)
{
	struct pci_dev *pdev = to_pci_dev(device);
	struct ishtp_device *dev = pci_get_drvdata(pdev);
	int ret = 0;

	if (dev->pdev->device == EHL_Ax_DEVICE_ID) {
		pci_set_power_state(pdev, PCI_D0);
		enable_pme_wake(pdev);

		ret = ish_notify_d0(dev);
	}

	if (!ret)
		pm_runtime_mark_last_busy(device);

	return ret;
}

static const struct dev_pm_ops __maybe_unused ish_pm_ops = {
	.suspend = ish_pm_suspend,
	.resume = ish_pm_resume,
	.freeze = ish_pm_freeze,
	.thaw = ish_pm_thaw,
	.poweroff = ish_pm_poweroff,
	.restore = ish_pm_restore,
	.runtime_suspend = ish_runtime_suspend,
	.runtime_resume = ish_runtime_resume,
};

static struct pci_driver ish_driver = {
	.name = KBUILD_MODNAME,
	.id_table = ish_pci_tbl,
	.probe = ish_probe,
	.remove = ish_remove,
	.driver.pm = &ish_pm_ops,
};

module_pci_driver(ish_driver);

/* Original author */
MODULE_AUTHOR("Daniel Drubin <daniel.drubin@intel.com>");
/* Adoption to upstream Linux kernel */
MODULE_AUTHOR("Srinivas Pandruvada <srinivas.pandruvada@linux.intel.com>");

MODULE_DESCRIPTION("Intel(R) Integrated Sensor Hub PCI Device Driver");
MODULE_LICENSE("GPL");
