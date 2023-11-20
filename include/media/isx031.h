/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2014 - 2022 Intel Corporation */

#ifndef __ISX031_H
#define __ISX031_H

#include <linux/types.h>

#define ISX031_NAME "isx031"

struct isx031_platform_data {
	unsigned int port;
	unsigned int lanes;
	uint32_t i2c_slave_address;
	int irq_pin;
	unsigned int irq_pin_flags;
	char irq_pin_name[16];
	char suffix;
	int gpios[4];
};

#endif /* __ISX031_H  */
