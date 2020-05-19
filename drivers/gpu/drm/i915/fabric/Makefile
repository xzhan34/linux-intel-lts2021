# SPDX-License-Identifier: MIT
#
# Copyright(c) 2020 - 2022 Intel Corporation.
#
# Intel Connectivity fabric driver
#

obj-$(CONFIG_DRM_I915_INTEL_FABRIC) += iaf.o

iaf-y := debugfs.o \
	 dev_diag.o \
	 error.o \
	 fw.o \
	 main.o \
	 mei_iaf_user.o \
	 mbdb.o \
	 ops.o \
	 port.o \
	 port_diag.o \
	 statedump.o \
	 sysfs.o \
	 trace.o \

CFLAGS_trace.o = -I$(src)
