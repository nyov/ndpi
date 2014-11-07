/*
 * proto_usenet.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
 * Copyright (C) 2014 Tomasz Bujlow <tomasz@bujlow.com>
 *
 * This file is part of nDPIng, an open source deep packet inspection
 * library based on nDPI, OpenDPI, and PACE technology by ipoque GmbH
 *
 * nDPIng is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPIng is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPIng.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#include "ndpi_api.h"

void ndpi_search_usenet_tcp(struct ndpi_detection_module_struct
							  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "USENET: search usenet.\n");
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "USENET: STAGE IS %u.\n", flow->l4.tcp.usenet_stage);


	// check for the first server replay
	/*
	   200    Service available, posting allowed
	   201    Service available, posting prohibited
	 */
	if (flow->l4.tcp.usenet_stage == 0 && packet->payload_packet_len > 10
		&& ((memcmp(packet->payload, "200 ", 4) == 0)
			|| (memcmp(packet->payload, "201 ", 4) == 0))) {

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "USENET: found 200 or 201.\n");
		flow->l4.tcp.usenet_stage = 1 + packet->packet_direction;

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "USENET: maybe hit.\n");
		return;
	}

	/*
	   [C] AUTHINFO USER fred
	   [S] 381 Enter passphrase
	   [C] AUTHINFO PASS flintstone
	   [S] 281 Authentication accepted
	 */
	// check for client username
	if (flow->l4.tcp.usenet_stage == 2 - packet->packet_direction) {
		if (packet->payload_packet_len > 20 && (memcmp(packet->payload, "AUTHINFO USER ", 14) == 0)) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "USENET: username found\n");
			flow->l4.tcp.usenet_stage = 3 + packet->packet_direction;

			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "USENET: found usenet.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_USENET;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_USENET] = 1;
			return;
		} else if (packet->payload_packet_len == 13 && (memcmp(packet->payload, "MODE READER\r\n", 13) == 0)) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
					"USENET: no login necessary but we are a client.\n");

			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "USENET: found usenet.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_USENET;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_USENET] = 1;
			return;
		}
	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "USENET: exclude usenet.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_USENET] = 1;
}

void ndpi_register_proto_usenet (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_USENET, "Usenet", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_usenet_tcp);
}
