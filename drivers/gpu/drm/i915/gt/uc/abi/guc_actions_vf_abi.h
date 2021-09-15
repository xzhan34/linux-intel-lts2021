/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2021 Intel Corporation
 */

#ifndef _ABI_GUC_ACTIONS_VF_ABI_H
#define _ABI_GUC_ACTIONS_VF_ABI_H

#include "guc_communication_mmio_abi.h"

/**
 * DOC: VF2GUC_MATCH_VERSION
 *
 * This action is used to match VF interface version used by VF and GuC.
 *
 * This action must be sent over MMIO.
 *
 *  +---+-------+--------------------------------------------------------------+
 *  |   | Bits  | Description                                                  |
 *  +===+=======+==============================================================+
 *  | 0 |    31 | ORIGIN = GUC_HXG_ORIGIN_HOST_                                |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 30:28 | TYPE = GUC_HXG_TYPE_REQUEST_                                 |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 27:16 | DATA0 = MBZ                                                  |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  15:0 | ACTION = _`GUC_ACTION_VF2GUC_MATCH_VERSION` = 0x5500         |
 *  +---+-------+--------------------------------------------------------------+
 *  | 1 | 31:24 | **BRANCH** - branch ID of the VF interface                   |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 23:16 | **MAJOR** - major version of the VF interface                |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  15:8 | **MINOR** - minor version of the VF interface                |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |   7:0 | **MBZ**                                                      |
 *  +---+-------+--------------------------------------------------------------+
 *
 *  +---+-------+--------------------------------------------------------------+
 *  |   | Bits  | Description                                                  |
 *  +===+=======+==============================================================+
 *  | 0 |    31 | ORIGIN = GUC_HXG_ORIGIN_GUC_                                 |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 30:28 | TYPE = GUC_HXG_TYPE_RESPONSE_SUCCESS_                        |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  27:0 | DATA0 = MBZ                                                  |
 *  +---+-------+--------------------------------------------------------------+
 *  | 1 | 31:24 | **BRANCH** - branch ID of the VF interface                   |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 23:16 | **MAJOR** - major version of the VF interface                |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  15:8 | **MINOR** - minor version of the VF interface                |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |   7:0 | **PATCH** - patch version of the VF interface                |
 *  +---+-------+--------------------------------------------------------------+
 */
#define GUC_ACTION_VF2GUC_MATCH_VERSION			0x5500

#define VF2GUC_MATCH_VERSION_REQUEST_MSG_LEN		(GUC_HXG_REQUEST_MSG_MIN_LEN + 1u)
#define VF2GUC_MATCH_VERSION_REQUEST_MSG_0_MBZ		GUC_HXG_REQUEST_MSG_0_DATA0
#define VF2GUC_MATCH_VERSION_REQUEST_MSG_1_BRANCH	(0xff << 24)
#define   GUC_VERSION_BRANCH_ANY			0
#define VF2GUC_MATCH_VERSION_REQUEST_MSG_1_MAJOR	(0xff << 16)
#define   GUC_VERSION_MAJOR_ANY				0
#define VF2GUC_MATCH_VERSION_REQUEST_MSG_1_MINOR	(0xff << 8)
#define   GUC_VERSION_MINOR_ANY				0
#define VF2GUC_MATCH_VERSION_REQUEST_MSG_1_MBZ		(0xff << 0)

#define VF2GUC_MATCH_VERSION_RESPONSE_MSG_LEN		(GUC_HXG_RESPONSE_MSG_MIN_LEN + 1u)
#define VF2GUC_MATCH_VERSION_RESPONSE_MSG_0_MBZ		GUC_HXG_RESPONSE_MSG_0_DATA0
#define VF2GUC_MATCH_VERSION_RESPONSE_MSG_1_BRANCH	(0xff << 24)
#define VF2GUC_MATCH_VERSION_RESPONSE_MSG_1_MAJOR	(0xff << 16)
#define VF2GUC_MATCH_VERSION_RESPONSE_MSG_1_MINOR	(0xff << 8)
#define VF2GUC_MATCH_VERSION_RESPONSE_MSG_1_PATCH	(0xff << 0)

/**
 * DOC: VF2GUC_VF_RESET
 *
 * This action is used by VF to reset GuC's VF state.
 *
 * This message must be sent as `MMIO HXG Message`_.
 *
 *  +---+-------+--------------------------------------------------------------+
 *  |   | Bits  | Description                                                  |
 *  +===+=======+==============================================================+
 *  | 0 |    31 | ORIGIN = GUC_HXG_ORIGIN_HOST_                                |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 30:28 | TYPE = GUC_HXG_TYPE_REQUEST_                                 |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 27:16 | DATA0 = MBZ                                                  |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  15:0 | ACTION = _`GUC_ACTION_VF2GUC_VF_RESET` = 0x5507              |
 *  +---+-------+--------------------------------------------------------------+
 *
 *  +---+-------+--------------------------------------------------------------+
 *  |   | Bits  | Description                                                  |
 *  +===+=======+==============================================================+
 *  | 0 |    31 | ORIGIN = GUC_HXG_ORIGIN_GUC_                                 |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 30:28 | TYPE = GUC_HXG_TYPE_RESPONSE_SUCCESS_                        |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  27:0 | DATA0 = MBZ                                                  |
 *  +---+-------+--------------------------------------------------------------+
 */
#define GUC_ACTION_VF2GUC_VF_RESET			0x5507

#define VF2GUC_VF_RESET_REQUEST_MSG_LEN			GUC_HXG_REQUEST_MSG_MIN_LEN
#define VF2GUC_VF_RESET_REQUEST_MSG_0_MBZ		GUC_HXG_REQUEST_MSG_0_DATA0

#define VF2GUC_VF_RESET_RESPONSE_MSG_LEN		GUC_HXG_RESPONSE_MSG_MIN_LEN
#define VF2GUC_VF_RESET_RESPONSE_MSG_0_MBZ		GUC_HXG_RESPONSE_MSG_0_DATA0

#endif /* _ABI_GUC_ACTIONS_VF_ABI_H */
