/* SPDX-License-Identifier: MIT */
/*
 * Copyright(c) 2020 - 2022 Intel Corporation.
 */

#ifndef IAF_DRV_H_INCLUDED
#define IAF_DRV_H_INCLUDED

#if IS_ENABLED(CONFIG_AUXILIARY_BUS)
#include <linux/auxiliary_bus.h>
#else
#include <linux/platform_device.h>
#endif
#include <linux/irqreturn.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/kref.h>

#include <drm/intel_iaf_platform.h>

#define DRIVER_NAME "iaf"

#undef pr_fmt
#define pr_fmt(fmt) DRIVER_NAME ": " fmt

/*
 * The maximum number of tiles for the PVC product type.
 *
 * Revisit if future product types or variations are developed that require
 * a product type table.
 */
#define IAF_MAX_SUB_DEVS 2

/*
 * Recognized discrete socket IDs
 */
#define MAX_SOCKET_IDS (32)

/*
 * Platforms and revisions.
 *
 * Note that these conform to the ANR ASIC_REV_INFO (ARI) register values,
 * not the PCI revision IDs reported by the packaged product.
 */

#define ANR_ARI_PLATFORM	0x0101

#define ANR_ARI_STEP_A0		0x00
#define ANR_ARI_STEP_A1		0x01
#define ANR_ARI_STEP_A_LAST	ANR_ARI_STEP_A1
#define ANR_ARI_STEP_B0		0x10
#define ANR_ARI_STEP_B_LAST	ANR_ARI_STEP_B0

#define IS_ANR(sd) \
	(FIELD_GET(MASK_ARI_PLATFORM, (sd)->asic_rev_info) == ANR_ARI_PLATFORM)

#define IS_ANR_STEP(sd, since, until) (IS_ANR(sd) && \
	FIELD_GET(MASK_ARI_STEP, (sd)->asic_rev_info) >= (since) && \
	FIELD_GET(MASK_ARI_STEP, (sd)->asic_rev_info) <= (until))

/*
 * Device and subdevice message formats
 *
 * Device expands dev->name, sd expand relevant indices
 * ": " separates info. *_FMT ends in ": ", *_ID_FMT does not
 */

#define DEV_ID_FMT "iaf.%d"
#define SD_ID_FMT "sd.%d"

#define DEV_FMT DEV_ID_FMT ": "
#define SD_FMT SD_ID_FMT ": "

#define DEV_SD_FMT DEV_FMT "" SD_FMT

/*
 * Subdevice-specific messaging
 */

#define sd_emerg(__sd, _fmt, ...) \
		do { \
			struct fsubdev *_sd = (__sd); \
			dev_emerg(sd_dev(_sd), SD_FMT _fmt, \
				  sd_index(_sd), ##__VA_ARGS__); \
		} while (0)

#define sd_alert(__sd, _fmt, ...) \
		do { \
			struct fsubdev *_sd = (__sd); \
			dev_alert(sd_dev(_sd), SD_FMT _fmt, \
				  sd_index(_sd), ##__VA_ARGS__); \
		} while (0)

#define sd_crit(__sd, _fmt, ...) \
		do { \
			struct fsubdev *_sd = (__sd); \
			dev_crit(sd_dev(_sd), SD_FMT _fmt, \
				 sd_index(_sd), ##__VA_ARGS__); \
		} while (0)

#define sd_err(__sd, _fmt, ...) \
		do { \
			struct fsubdev *_sd = (__sd); \
			dev_err(sd_dev(_sd), SD_FMT _fmt, \
				sd_index(_sd), ##__VA_ARGS__); \
		} while (0)

#define sd_warn(__sd, _fmt, ...) \
		do { \
			struct fsubdev *_sd = (__sd); \
			dev_warn(sd_dev(_sd), SD_FMT _fmt, \
				 sd_index(_sd), ##__VA_ARGS__); \
		} while (0)

#define sd_notice(__sd, _fmt, ...) \
		do { \
			struct fsubdev *_sd = (__sd); \
			dev_notice(sd_dev(_sd), SD_FMT _fmt, \
				   sd_index(_sd), ##__VA_ARGS__); \
		} while (0)

#define sd_info(__sd, _fmt, ...) \
		do { \
			struct fsubdev *_sd = (__sd); \
			dev_info(sd_dev(_sd), SD_FMT _fmt, \
				 sd_index(_sd), ##__VA_ARGS__); \
		} while (0)

#define sd_dbg(__sd, _fmt, ...) \
		do { \
			struct fsubdev *_sd = (__sd); \
			dev_dbg(sd_dev(_sd), SD_FMT _fmt, \
				sd_index(_sd), ##__VA_ARGS__); \
		} while (0)

enum iaf_startup_mode {
	STARTUP_MODE_DEFAULT = 0,
	STARTUP_MODE_PRELOAD = 1,
#if IS_ENABLED(CONFIG_IAF_DEBUG_STARTUP)
	STARTUP_MODE_DEBUG   = 2,
	STARTUP_MODE_FWDEBUG = 3,
#endif
};

struct fsubdev; /* from this file */

struct fdev; /* from this file */

/**
 * enum sd_error - Subdevice error conditions
 * @SD_ERROR_FAILED: Subdevice has been marked as FAILED
 * @SD_ERROR_FW: Firmware error
 * @NUM_SD_ERRORS: Number of error conditions (always last)
 */
enum sd_error {
	SD_ERROR_FAILED,
	SD_ERROR_FW,
	NUM_SD_ERRORS
};

/**
 * struct fsubdev - Per-subdevice state
 * @fdev: link to containing device
 * @csr_base: base address of this subdevice's memory
 * @irq: assigned interrupt
 * @name: small string to describe SD
 * @asic_rev_info: raw contents of the asic rev info register
 * @kobj: kobject for this sd in the sysfs tree
 * @sd_failure: attribute for sd_failure sysfs file
 * @guid: GUID retrieved from firmware
 * @port_cnt: count of all fabric ports
 * @errors: bitmap of active error states
 *
 * Used throughout the driver to maintain information about a given subdevice.
 *
 * Protection mechanisms used outside of init/destroy are documented inline. Sync probe is the
 * context of the initial probe function. Async probe includes the initialization threads used to
 * load the firmware and platform configuration before enabling general processing.
 */
struct fsubdev {
	/* pointers const after sync probe, content protection is by object type */
	struct fdev *fdev;
	char __iomem *csr_base;

	/* values const after sync probe */
	int irq;
	char name[8];
	u64 asic_rev_info;

	/* values const after async probe */
	struct kobject *kobj;
	struct device_attribute sd_failure;

	u64 guid;
	u8 port_cnt;

	/* atomic, never cleared after sync probe */
	DECLARE_BITMAP(errors, NUM_SD_ERRORS);
};

/**
 * struct fdev - Device structure for IAF/fabric device component
 * @sd: subdevice structures
 * @dev_disabled: On a PCIe error, disable access to the PCI bus
 * @pdev: bus device passed in probe
 * @pd: platform specific data
 * @fabric_id: xarray index based on parent index and product type
 * @mappings_ref.lock: protect the mappings_ref data
 * @mappings_ref.count: current mapped buffer count
 * @mappings_ref.remove_in_progress: indicate unmap should show completion
 * @mappings_ref.complete: completion after all buffers are unmapped
 * @mappings_ref: Reference count of parent mapped buffers
 * @refs: references on this instance
 * @fdev_released: signals fdev has been erased from the xarray
 * @startup_mode: startup mode
 *
 * Used throughout the driver to maintain information about a given device.
 */
struct fdev {
	struct fsubdev sd[IAF_MAX_SUB_DEVS];
	bool dev_disabled;
#if IS_ENABLED(CONFIG_AUXILIARY_BUS)
	struct auxiliary_device *pdev;
#else
	struct platform_device *pdev;
#endif
	const struct iaf_pdata *pd;
	u32 fabric_id;

	struct {
		/* protect the mapping count and remove_in_progress flag */
		struct mutex lock;
		int count;
		bool remove_in_progress;
		struct completion complete;
	} mappings_ref;

	struct kref refs;
	struct completion fdev_released;
	enum iaf_startup_mode startup_mode;
};

void fdev_put(struct fdev *dev);
int fdev_insert(struct fdev *dev);

/*
 * This is the fdev_process_each callback function signature
 * Returning 0 indicates continue
 * Any other return value indicates terminate
 */
typedef int (*fdev_process_each_cb_t)(struct fdev *dev, void *args);

int fdev_process_each(fdev_process_each_cb_t cb, void *args);

struct fdev *fdev_find(u32 fabric_id);

/*
 * Returns the sd index/offset relative to its device.
 */
static inline u8 sd_index(struct fsubdev *sd)
{
	return sd - sd->fdev->sd;
}

/*
 * dev_is_startup_debug - Test for full debug startup mode.
 * @dev: device
 *
 * Return: True if we're actually starting up straight into debug mode,
 * bypassing all normal device init behavior.
 */
static inline bool dev_is_startup_debug(struct fdev *dev)
{
#if IS_ENABLED(CONFIG_IAF_DEBUG_STARTUP)
	return dev && dev->startup_mode == STARTUP_MODE_DEBUG;
#else
	return false;
#endif
}

/**
 * dev_is_runtime_debug - Test for runtime debug startup mode.
 * @dev: device
 *
 * Return: True if, regardless of the startup logic, we end up in debug mode
 * once we're past firmware init.
 */
static inline bool dev_is_runtime_debug(struct fdev *dev)
{
#if IS_ENABLED(CONFIG_IAF_DEBUG_STARTUP)
	return dev && (dev->startup_mode == STARTUP_MODE_DEBUG ||
		       dev->startup_mode == STARTUP_MODE_FWDEBUG);
#else
	return false;
#endif
}

/*
 * dev_is_preload - Test for preload startup mode.
 * @dev: device
 *
 * Return: True if the device is in preload startup mode.
 */
static inline bool dev_is_preload(struct fdev *dev)
{
	return dev && dev->startup_mode == STARTUP_MODE_PRELOAD;
}

static inline struct device *sd_dev(const struct fsubdev *sd)
{
	return &sd->fdev->pdev->dev;
}

static inline struct device *fdev_dev(const struct fdev *dev)
{
	return &dev->pdev->dev;
}

/* The following two functions increase device reference count: */
struct fdev *fdev_find_by_sd_guid(u64 guid);
struct fsubdev *find_sd_id(u32 fabric_id, u8 sd_index);

#endif
