/*
 * proto_crossfire.c
 *
 * Copyright (C) 2012-13 - ntop.org
 * Copyright (C) 2014 Tomasz Bujlow <tomasz@skatnet.dk>
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

#include "ndpi_protocols.h"

void ndpi_search_crossfire(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search crossfire.\n");


	if (packet->udp != 0) {
		if (packet->payload_packet_len == 25 && get_u_int32_t(packet->payload, 0) == ntohl(0xc7d91999)
			&& get_u_int16_t(packet->payload, 4) == ntohs(0x0200)
			&& get_u_int16_t(packet->payload, 22) == ntohs(0x7d00)
			) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Crossfire: found udp packet.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_CROSSFIRE;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_CROSSFIRE] = 1;
			return;
		}

	} else if (packet->tcp != 0) {

		if (packet->payload_packet_len > 4 && memcmp(packet->payload, "GET /", 5) == 0) {
			ndpi_parse_packet_line_info(ndpi_struct, flow);
			if (packet->parsed_lines == 8
				&& (packet->line[0].ptr != NULL && packet->line[0].len >= 30
					&& (memcmp(&packet->payload[5], "notice/login_big", 16) == 0
						|| memcmp(&packet->payload[5], "notice/login_small", 18) == 0))
				&& memcmp(&packet->payload[packet->line[0].len - 19], "/index.asp HTTP/1.", 18) == 0
				&& (packet->host_line.ptr != NULL && packet->host_line.len >= 13
					&& (memcmp(packet->host_line.ptr, "crossfire", 9) == 0
						|| memcmp(packet->host_line.ptr, "www.crossfire", 13) == 0))
				) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Crossfire: found HTTP request.\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_CROSSFIRE;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_CROSSFIRE] = 1;
				return;
			}
		}

	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude crossfire.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_CROSSFIRE] = 1;
}

void ndpi_register_proto_crossfire (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_CROSSFIRE, "Crossfire", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_crossfire);
}
