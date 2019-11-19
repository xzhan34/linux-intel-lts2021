/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef _ABI_IOV_ACTIONS_ABI_H_
#define _ABI_IOV_ACTIONS_ABI_H_

#include "iov_messages_abi.h"

/**
 * DOC: IOV Actions
 *
 * TBD
 */

/**
 * DOC: VF2PF_HANDSHAKE
 *
 * This `IOV Message`_ is used by the VF to establish ABI version with the PF.
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
 *  |   |  15:0 | ACTION = _`IOV_ACTION_VF2PF_HANDSHAKE` = 0x0001              |
 *  +---+-------+--------------------------------------------------------------+
 *  | 1 | 31:16 | **MAJOR** - requested major version of the VFPF interface    |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  15:0 | **MINOR** - requested minor version of the VFPF interface    |
 *  +---+-------+--------------------------------------------------------------+
 *
 *  +---+-------+--------------------------------------------------------------+
 *  |   | Bits  | Description                                                  |
 *  +===+=======+==============================================================+
 *  | 0 |    31 | ORIGIN = GUC_HXG_ORIGIN_HOST_                                |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 30:28 | TYPE = GUC_HXG_TYPE_RESPONSE_SUCCESS_                        |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  27:0 | DATA0 = MBZ                                                  |
 *  +---+-------+--------------------------------------------------------------+
 *  | 1 | 31:16 | **MAJOR** - agreed major version of the VFPF interface       |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  15:0 | **MINOR** - agreed minor version of the VFPF interface       |
 *  +---+-------+--------------------------------------------------------------+
 */
#define IOV_ACTION_VF2PF_HANDSHAKE			0x0001

#define VF2PF_HANDSHAKE_REQUEST_MSG_LEN			2u
#define VF2PF_HANDSHAKE_REQUEST_MSG_0_MBZ		GUC_HXG_REQUEST_MSG_0_DATA0
#define VF2PF_HANDSHAKE_REQUEST_MSG_1_MAJOR		(0xffff << 16)
#define VF2PF_HANDSHAKE_REQUEST_MSG_1_MINOR		(0xffff << 0)

#define VF2PF_HANDSHAKE_RESPONSE_MSG_LEN		2u
#define VF2PF_HANDSHAKE_RESPONSE_MSG_0_MBZ		GUC_HXG_RESPONSE_MSG_0_DATA0
#define VF2PF_HANDSHAKE_RESPONSE_MSG_1_MAJOR		(0xffff << 16)
#define VF2PF_HANDSHAKE_RESPONSE_MSG_1_MINOR		(0xffff << 0)

#endif /* _ABI_IOV_ACTIONS_ABI_H_ */
