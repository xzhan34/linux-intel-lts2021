// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright(c) 2021 Intel Corporation. All rights reserved.
//
// Authors: Cezary Rojewski <cezary.rojewski@intel.com>
//          Amadeusz Slawinski <amadeuszx.slawinski@linux.intel.com>
//

#include "avs.h"

static int
tgl_dsp_core_power(struct avs_dev *adev, u32 core_mask, bool power)
{
	core_mask &= AVS_MAIN_CORE_MASK;

	if (!core_mask)
		return 0;
	return avs_dsp_core_power(adev, core_mask, power);
}

static int
tgl_dsp_core_reset(struct avs_dev *adev, u32 core_mask, bool reset)
{
	core_mask &= AVS_MAIN_CORE_MASK;

	if (!core_mask)
		return 0;
	return avs_dsp_core_reset(adev, core_mask, reset);
}

static int
tgl_dsp_core_stall(struct avs_dev *adev, u32 core_mask, bool stall)
{
	core_mask &= AVS_MAIN_CORE_MASK;

	if (!core_mask)
		return 0;
	return avs_dsp_core_stall(adev, core_mask, stall);
}

const struct avs_dsp_ops tgl_dsp_ops = {
	.power = tgl_dsp_core_power,
	.reset = tgl_dsp_core_reset,
	.stall = tgl_dsp_core_stall,
	.irq_handler = avs_ipc_irq_handler,
	.irq_thread = cnl_ipc_irq_thread,
	.int_control = avs_dsp_interrupt_control,
	.load_basefw = avs_hda_load_basefw,
	.load_lib = avs_hda_load_library,
	.transfer_mods = avs_hda_transfer_modules,
	.log_buffer_offset = icl_log_buffer_offset,
	.log_buffer_status = apl_log_buffer_status,
	.coredump = apl_coredump,
	.d0ix_toggle = icl_d0ix_toggle,
	.set_d0ix = icl_set_d0ix,
	AVS_SET_ENABLE_LOGS_OP(icl)
};
