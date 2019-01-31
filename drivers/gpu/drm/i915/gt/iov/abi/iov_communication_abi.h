/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef _ABI_IOV_COMMUNICATION_ABI_H_
#define _ABI_IOV_COMMUNICATION_ABI_H_

#include "gt/uc/abi/guc_communication_ctb_abi.h"

/**
 * DOC: IOV Communication
 *
 * The communication between VFs and PF is based on the relay messages with GuC
 * acting a proxy agent. All relay messages are defined as `CTB HXG Message`_.
 * The `IOV Message`_ is embedded in these messages as opaque payload.
 *
 * The `IOV Message`_ from a VF is delivered to the PF in `GUC2PF_RELAY_FROM_VF`_.
 * This message contains also identifier of the origin VF and message identifier
 * that is used in any replies.
 *
 *  +--------------------------------------------------------------------------+
 *  |  `CTB Message`_                                                          |
 *  |                                                                          |
 *  +===+======================================================================+
 *  |   |  `CTB HXG Message`_                                                  |
 *  |   |                                                                      |
 *  |   +---+------------------------------------------------------------------+
 *  |   |   | `HXG Message`_                                                   |
 *  |   |   |                                                                  |
 *  |   |   +---+--------------------------------------------------------------+
 *  |   |   |   |  `HXG Request`_                                              |
 *  |   |   |   |                                                              |
 *  |   |   |   +---+----------------------------------------------------------+
 *  |   |   |   |   |  `GUC2PF_RELAY_FROM_VF`_                                 |
 *  |   |   |   |   |                                                          |
 *  |   |   |   |   +------------+------------+--------------------------------+
 *  |   |   |   |   |            |            | +----------------------------+ |
 *  |   |   |   |   |   Origin   | Message ID | |     `IOV Message`_         | |
 *  |   |   |   |   |            |            | +----------------------------+ |
 *  +---+---+---+---+------------+------------+--------------------------------+
 *
 * To send `IOV Message`_ to the particular VF, PF is using `PF2GUC_RELAY_TO_VF`_
 * that takes target VF identifier and the message identifier.
 *
 *  +--------------------------------------------------------------------------+
 *  |  `CTB Message`_                                                          |
 *  |                                                                          |
 *  +===+======================================================================+
 *  |   |  `CTB HXG Message`_                                                  |
 *  |   |                                                                      |
 *  |   +---+------------------------------------------------------------------+
 *  |   |   | `HXG Message`_                                                   |
 *  |   |   |                                                                  |
 *  |   |   +---+--------------------------------------------------------------+
 *  |   |   |   |  `HXG Request`_                                              |
 *  |   |   |   |                                                              |
 *  |   |   |   +---+----------------------------------------------------------+
 *  |   |   |   |   |  `PF2GUC_RELAY_TO_VF`_                                   |
 *  |   |   |   |   |                                                          |
 *  |   |   |   |   +------------+------------+--------------------------------+
 *  |   |   |   |   |            |            | +----------------------------+ |
 *  |   |   |   |   |   Target   | Message ID | |     `IOV Message`_         | |
 *  |   |   |   |   |            |            | +----------------------------+ |
 *  +---+---+---+---+------------+------------+--------------------------------+
 */

#endif /* _ABI_IOV_COMMUNICATION_ABI_H_ */
