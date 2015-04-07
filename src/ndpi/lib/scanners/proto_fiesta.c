/*
 * proto_fiesta.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
 * Copyright (C) 2014-15 Tomasz Bujlow <tomasz@bujlow.com>
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

void ndpi_search_fiesta(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search fiesta.\n");

	if (flow->l4.tcp.fiesta_stage == 0 && packet->payload_packet_len == 5
		&& get_u_int16_t(packet->payload, 0) == ntohs(0x0407)
		&& (packet->payload[2] == 0x08)
		&& (packet->payload[4] == 0x00 || packet->payload[4] == 0x01)) {

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe fiesta symmetric, first packet.\n");
		flow->l4.tcp.fiesta_stage = 1 + packet->packet_direction;
		goto maybe_fiesta;
	}
	
	if (flow->l4.tcp.fiesta_stage == (2 - packet->packet_direction)
		&& ((packet->payload_packet_len > 1 && packet->payload_packet_len - 1 == packet->payload[0])
			|| (packet->payload_packet_len > 3 && packet->payload[0] == 0
				&& get_l16(packet->payload, 1) == packet->payload_packet_len - 3))) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Maybe fiesta.\n");
		goto maybe_fiesta;
	}
	
	if (flow->l4.tcp.fiesta_stage == (1 + packet->packet_direction)) {
		if (packet->payload_packet_len == 4 && get_u_int32_t(packet->payload, 0) == htonl(0x03050c01)) {
			goto add_fiesta;
		}
		if (packet->payload_packet_len == 5 && get_u_int32_t(packet->payload, 0) == htonl(0x04030c01)
			&& packet->payload[4] == 0) {
			goto add_fiesta;
		}
		if (packet->payload_packet_len == 6 && get_u_int32_t(packet->payload, 0) == htonl(0x050e080b)) {
			goto add_fiesta;
		}
		if (packet->payload_packet_len == 100 && packet->payload[0] == 0x63 && packet->payload[61] == 0x52
			&& packet->payload[81] == 0x5a && get_u_int16_t(packet->payload, 1) == htons(0x3810)
			&& get_u_int16_t(packet->payload, 62) == htons(0x6f75)) {
			goto add_fiesta;
		}
		if (packet->payload_packet_len > 3 && packet->payload_packet_len - 1 == packet->payload[0]
			&& get_u_int16_t(packet->payload, 1) == htons(0x140c)) {
			goto add_fiesta;
		}
	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude fiesta.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_FIESTA] = 1;
	return;

  maybe_fiesta:
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Stage is set to %d.\n", flow->l4.tcp.fiesta_stage);
	return;

  add_fiesta:
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "detected fiesta.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_FIESTA;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_FIESTA] = 1;
	return;
}

void ndpi_register_proto_fiesta (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_FIESTA, "Fiesta", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_fiesta);
}
