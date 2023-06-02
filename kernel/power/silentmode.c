// SPDX-License-Identifier: GPL-2.0-only
/*
 * silentmode.c - for automative silentmode support
 *
 * Copyright (C) 2023, Intel Corporation.
 * Austin Sun <austin.sun@intel.com>
 */
#include "asm/cmdline.h"
#include "power.h"
#include "linux/kernel.h"
#include "linux/init.h"
#include "linux/string.h"

#ifdef CONFIG_PM_SILENTMODE
#define MAX_PARA_LEN 32
static atomic_t pm_silentmode_kernel_state = ATOMIC_INIT(PM_SILENTMODE_NORMAL);
static atomic_t pm_silentmode_hw_state = ATOMIC_INIT(PM_SILENTMODE_NORMAL);
static char pm_sm_bootstr[] = "silentmode";


void pm_silentmode_kernel_state_set(int mode)
{
	atomic_set(&pm_silentmode_kernel_state, mode);
	sysfs_notify(power_kobj, NULL, "pm_silentmode_kernel_state");
}

EXPORT_SYMBOL(pm_silentmode_kernel_state_set);

int pm_silentmode_kernel_state_get(void)
{
	return atomic_read(&pm_silentmode_kernel_state);
}

EXPORT_SYMBOL(pm_silentmode_kernel_state_get);

void pm_silentmode_hw_state_set(int mode)
{
	atomic_set(&pm_silentmode_hw_state, mode);
	sysfs_notify(power_kobj, NULL, "pm_silentmode_hw_state");
}

int pm_silentmode_hw_state_get(void)
{
	return atomic_read(&pm_silentmode_hw_state);
}

EXPORT_SYMBOL(pm_silentmode_hw_state_get);

static int pm_silentmode_get_cmdline(void)
{
	int len;
	char para[MAX_PARA_LEN] = { };
	len = cmdline_find_option(saved_command_line, pm_sm_bootstr, para, MAX_PARA_LEN);
	if(len < 0){
		pr_info("silentmode not specified\n");
		return PM_SILENTMODE_NORMAL;
	}

	pr_info("pm_silentmode = %s\n", para);
	if (strnstr(para, "silent", strlen(para))) {
		pr_info("pm_silentmode is set to silent\n");
		pm_silentmode_hw_state_set(PM_SILENTMODE_SILENT);
		pm_silentmode_kernel_state_set(PM_SILENTMODE_SILENT);
		return PM_SILENTMODE_SILENT;
	}

	pr_info("set silentmode normal\n");
	return PM_SILENTMODE_NORMAL;
}
void __init pm_silentmode_init(void)
{
	int mode;
	mode = pm_silentmode_get_cmdline();
	if (mode == PM_SILENTMODE_SILENT)
		pr_debug("PM Silent Boot Mode is set\n");
	pr_info("PM Silent Boot Mode is set normal \n");
}
#endif	// CONFIG_PM_SILENTMODE
