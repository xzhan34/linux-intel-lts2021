# SPDX-License-Identifier: MIT
#
# Copyright(c) 2020 - 2022 Intel Corporation.
#
# Intel Connectivity fabric driver
#
#

obj-$(CONFIG_DRM_I915_INTEL_FABRIC) += iaf.o

iaf-y := debugfs.o \
	 main.o \
	 mbdb.o \
	 sysfs.o \
	 trace.o \

CFLAGS_trace.o = -I$(src)
