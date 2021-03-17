/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2021 Intel Corporation
 */

#ifndef __GUC_ACTIONS_PF_ABI_H__
#define __GUC_ACTIONS_PF_ABI_H__

#include "guc_communication_ctb_abi.h"

/**
 * DOC: PF2GUC_UPDATE_VF_CFG
 *
 * The `PF2GUC_UPDATE_VF_CFG`_ message is used by PF to provision single VF in GuC.
 *
 * This message must be sent as `CTB HXG Message`_.
 *
 *  +---+-------+--------------------------------------------------------------+
 *  |   | Bits  | Description                                                  |
 *  +===+=======+==============================================================+
 *  | 0 |    31 | ORIGIN = GUC_HXG_ORIGIN_HOST_                                |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 30:28 | TYPE = GUC_HXG_TYPE_REQUEST_                                 |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 27:16 | MBZ                                                          |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  15:0 | ACTION = _`GUC_ACTION_PF2GUC_UPDATE_VF_CFG` = 0x5503         |
 *  +---+-------+--------------------------------------------------------------+
 *  | 1 |  31:0 | **VFID** - identifier of the VF that the KLV                 |
 *  |   |       | configurations are being applied to                          |
 *  +---+-------+--------------------------------------------------------------+
 *  | 2 |  31:0 | **CFG_ADDR_LO** - dword aligned GGTT offset that represents  |
 *  |   |       | the start of a list of virtualization related KLV configs    |
 *  |   |       | that are to be applied to the VF.                            |
 *  |   |       | If this parameter is zero, the list is not parsed.           |
 *  |   |       | If full configs address parameter is zero and configs_size is|
 *  |   |       | zero associated VF config shall be reset to its default state|
 *  +---+-------+--------------------------------------------------------------+
 *  | 3 |  31:0 | **CFG_ADDR_HI** - upper 32 bits of configs address.          |
 *  +---+-------+--------------------------------------------------------------+
 *  | 4 |  31:0 | **CFG_SIZE** - size (in dwords) of the config buffer         |
 *  +---+-------+--------------------------------------------------------------+
 *
 *  +---+-------+--------------------------------------------------------------+
 *  |   | Bits  | Description                                                  |
 *  +===+=======+==============================================================+
 *  | 0 |    31 | ORIGIN = GUC_HXG_ORIGIN_GUC_                                 |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 30:28 | TYPE = GUC_HXG_TYPE_RESPONSE_SUCCESS_                        |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  27:0 | **COUNT** - number of KLVs successfully applied              |
 *  +---+-------+--------------------------------------------------------------+
 */
#define GUC_ACTION_PF2GUC_UPDATE_VF_CFG			0x5503

#define PF2GUC_UPDATE_VF_CFG_REQUEST_MSG_LEN		(GUC_HXG_REQUEST_MSG_MIN_LEN + 4u)
#define PF2GUC_UPDATE_VF_CFG_REQUEST_MSG_0_MBZ		GUC_HXG_REQUEST_MSG_0_DATA0
#define PF2GUC_UPDATE_VF_CFG_REQUEST_MSG_1_VFID		GUC_HXG_REQUEST_MSG_n_DATAn
#define PF2GUC_UPDATE_VF_CFG_REQUEST_MSG_2_CFG_ADDR_LO	GUC_HXG_REQUEST_MSG_n_DATAn
#define PF2GUC_UPDATE_VF_CFG_REQUEST_MSG_3_CFG_ADDR_HI	GUC_HXG_REQUEST_MSG_n_DATAn
#define PF2GUC_UPDATE_VF_CFG_REQUEST_MSG_4_CFG_SIZE	GUC_HXG_REQUEST_MSG_n_DATAn

#define PF2GUC_UPDATE_VF_CFG_RESPONSE_MSG_LEN		GUC_HXG_RESPONSE_MSG_MIN_LEN
#define PF2GUC_UPDATE_VF_CFG_RESPONSE_MSG_0_COUNT	GUC_HXG_RESPONSE_MSG_0_DATA0

#endif /* __GUC_ACTIONS_PF_ABI_H__ */
