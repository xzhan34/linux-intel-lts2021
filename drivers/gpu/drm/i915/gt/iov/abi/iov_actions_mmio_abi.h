/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef _ABI_IOV_ACTIONS_MMIO_ABI_H_
#define _ABI_IOV_ACTIONS_MMIO_ABI_H_

#include "iov_messages_abi.h"

/**
 * DOC: IOV MMIO Opcodes
 *
 *  + _`IOV_OPCODE_VF2PF_MMIO_HANDSHAKE` = 0x01
 */

/**
 * DOC: VF2PF_MMIO_HANDSHAKE
 *
 * This VF2PF MMIO message is used by the VF to establish ABI version with the PF.
 *
 *  +---+-------+--------------------------------------------------------------+
 *  |   | Bits  | Description                                                  |
 *  +===+=======+==============================================================+
 *  | 0 |    31 | ORIGIN = GUC_HXG_ORIGIN_HOST_                                |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 30:28 | TYPE = GUC_HXG_TYPE_REQUEST_                                 |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 27:24 | MAGIC - see VF2GUC_MMIO_RELAY_SERVICE_                       |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 23:16 | OPCODE = IOV_OPCODE_VF2PF_MMIO_HANDSHAKE_                    |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  15:0 | ACTION = GUC_ACTION_VF2GUC_MMIO_RELAY_SERVICE_               |
 *  +---+-------+--------------------------------------------------------------+
 *  | 1 | 31:16 | **MAJOR** - requested major version of the VFPF interface    |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  15:0 | **MINOR** - requested minor version of the VFPF interface    |
 *  +---+-------+--------------------------------------------------------------+
 *  | 2 |  31:0 | MBZ                                                          |
 *  +---+-------+--------------------------------------------------------------+
 *  | 3 |  31:0 | MBZ                                                          |
 *  +---+-------+--------------------------------------------------------------+
 *
 *  +---+-------+--------------------------------------------------------------+
 *  |   | Bits  | Description                                                  |
 *  +===+=======+==============================================================+
 *  | 0 |    31 | ORIGIN = GUC_HXG_ORIGIN_HOST_                                |
 *  |   +-------+--------------------------------------------------------------+
 *  |   | 30:28 | TYPE = GUC_HXG_TYPE_RESPONSE_SUCCESS_                        |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  27:0 | MBZ                                                          |
 *  +---+-------+--------------------------------------------------------------+
 *  | 1 | 31:16 | **MAJOR** - agreed major version of the VFPF interface       |
 *  |   +-------+--------------------------------------------------------------+
 *  |   |  15:0 | **MINOR** - agreed minor version of the VFPF interface       |
 *  +---+-------+--------------------------------------------------------------+
 *  | 2 |  31:0 | MBZ                                                          |
 *  +---+-------+--------------------------------------------------------------+
 *  | 3 |  31:0 | MBZ                                                          |
 *  +---+-------+--------------------------------------------------------------+
 */
#define IOV_OPCODE_VF2PF_MMIO_HANDSHAKE			0x01

#define VF2PF_MMIO_HANDSHAKE_REQUEST_MSG_LEN		4u
#define VF2PF_MMIO_HANDSHAKE_REQUEST_MSG_1_MAJOR	(0xffff << 16)
#define VF2PF_MMIO_HANDSHAKE_REQUEST_MSG_1_MINOR	(0xffff << 0)

#define VF2PF_MMIO_HANDSHAKE_RESPONSE_MSG_LEN		4u
#define VF2PF_MMIO_HANDSHAKE_RESPONSE_MSG_0_MBZ		GUC_HXG_RESPONSE_MSG_0_DATA0
#define VF2PF_MMIO_HANDSHAKE_RESPONSE_MSG_1_MAJOR	(0xffff << 16)
#define VF2PF_MMIO_HANDSHAKE_RESPONSE_MSG_1_MINOR	(0xffff << 0)

#endif /* _ABI_IOV_ACTIONS_MMIO_ABI_H_ */
