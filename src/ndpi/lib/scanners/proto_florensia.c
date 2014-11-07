/*
 * proto_florensia.c
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

void ndpi_search_florensia(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search florensia.\n");

	if (packet->tcp != NULL) {
		if (packet->payload_packet_len == 5 && get_l16(packet->payload, 0) == packet->payload_packet_len
			&& packet->payload[2] == 0x65 && packet->payload[4] == 0xff) {
			if (flow->florensia_stage == 1) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found florensia.\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_FLORENSIA;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_FLORENSIA] = 1;
				return;
			}
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
			flow->florensia_stage = 1;
			return;
		}
		
		if (packet->payload_packet_len > 8 && get_l16(packet->payload, 0) == packet->payload_packet_len
			&& get_u_int16_t(packet->payload, 2) == htons(0x0201) && get_u_int32_t(packet->payload, 4) == htonl(0xFFFFFFFF)) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
			flow->florensia_stage = 1;
			return;
		}
		
		if (packet->payload_packet_len == 406 && get_l16(packet->payload, 0) == packet->payload_packet_len
			&& packet->payload[2] == 0x63) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
			flow->florensia_stage = 1;
			return;
		}
		
		if (packet->payload_packet_len == 12 && get_l16(packet->payload, 0) == packet->payload_packet_len
			&& get_u_int16_t(packet->payload, 2) == htons(0x0301)) {
			if (flow->florensia_stage == 1) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found florensia.\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_FLORENSIA;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_FLORENSIA] = 1;
				return;
			}
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
			flow->florensia_stage = 1;
			return;
		}

		if (flow->florensia_stage == 1) {
			if (packet->payload_packet_len == 8 && get_l16(packet->payload, 0) == packet->payload_packet_len
				&& get_u_int16_t(packet->payload, 2) == htons(0x0302) && get_u_int32_t(packet->payload, 4) == htonl(0xFFFFFFFF)) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found florensia asymmetrically.\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_FLORENSIA;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_FLORENSIA] = 1;
				return;
			}
			if (packet->payload_packet_len == 24 && get_l16(packet->payload, 0) == packet->payload_packet_len
				&& get_u_int16_t(packet->payload, 2) == htons(0x0202)
				&& get_u_int32_t(packet->payload, packet->payload_packet_len - 4) == htonl(0xFFFFFFFF)) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found florensia.\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_FLORENSIA;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_FLORENSIA] = 1;
				return;
			}
			if (flow->packet_counter < 10 && get_l16(packet->payload, 0) == packet->payload_packet_len) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe florensia.\n");
				return;
			}
		}
	}

	if (packet->udp != NULL) {
		if (flow->florensia_stage == 0 && packet->payload_packet_len == 6
			&& get_u_int16_t(packet->payload, 0) == ntohs(0x0503) && get_u_int32_t(packet->payload, 2) == htonl(0xFFFF0000)) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe florensia -> stage is set to 1.\n");
			flow->florensia_stage = 1;
			return;
		}
		
		if (flow->florensia_stage == 1 && packet->payload_packet_len == 8
			&& get_u_int16_t(packet->payload, 0) == ntohs(0x0500) && get_u_int16_t(packet->payload, 4) == htons(0x4191)) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found florensia.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_FLORENSIA;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_FLORENSIA] = 1;
			return;
		}
	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude florensia.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_FLORENSIA] = 1;
}

void ndpi_register_proto_florensia (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_FLORENSIA, "Florensia", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_florensia);
}
