/*
 * proto_maplestory.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
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

#include "ndpi_api.h"

void ndpi_search_maplestory(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	if (packet->payload_packet_len == 16
		&& (ntohl(get_u_int32_t(packet->payload, 0)) == 0x0e003a00 || ntohl(get_u_int32_t(packet->payload, 0)) == 0x0e003b00
			|| ntohl(get_u_int32_t(packet->payload, 0)) == 0x0e004200)
		&& ntohs(get_u_int16_t(packet->payload, 4)) == 0x0100 && (packet->payload[6] == 0x32 || packet->payload[6] == 0x33)) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found maplestory.\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_MAPLESTORY;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_MAPLESTORY] = 1;
		return;
	}

	if (packet->payload_packet_len > NDPI_STATICSTRING_LEN("GET /maple")
		&& memcmp(packet->payload, "GET /maple", NDPI_STATICSTRING_LEN("GET /maple")) == 0) {
		ndpi_parse_packet_line_info(ndpi_struct, flow);
		/* Maplestory update */
		if (packet->payload_packet_len > NDPI_STATICSTRING_LEN("GET /maple/patch")
			&& packet->payload[NDPI_STATICSTRING_LEN("GET /maple")] == '/') {
			if (packet->user_agent_line.ptr != NULL && packet->host_line.ptr != NULL
				&& packet->user_agent_line.len == NDPI_STATICSTRING_LEN("Patcher")
				&& packet->host_line.len > NDPI_STATICSTRING_LEN("patch.")
				&& memcmp(&packet->payload[NDPI_STATICSTRING_LEN("GET /maple/")], "patch",
						  NDPI_STATICSTRING_LEN("patch")) == 0
				&& memcmp(packet->user_agent_line.ptr, "Patcher", NDPI_STATICSTRING_LEN("Patcher")) == 0
				&& memcmp(packet->host_line.ptr, "patch.", NDPI_STATICSTRING_LEN("patch.")) == 0) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found maplestory update.\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_MAPLESTORY;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_MAPLESTORY] = 1;
				return;
			}
		} else if (packet->user_agent_line.ptr != NULL && packet->user_agent_line.len == NDPI_STATICSTRING_LEN("AspINet")
				   && memcmp(&packet->payload[NDPI_STATICSTRING_LEN("GET /maple")], "story/",
							 NDPI_STATICSTRING_LEN("story/")) == 0
				   && memcmp(packet->user_agent_line.ptr, "AspINet", NDPI_STATICSTRING_LEN("AspINet")) == 0) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found maplestory update.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_MAPLESTORY;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_MAPLESTORY] = 1;
			return;
		}
	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude maplestory.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_MAPLESTORY] = 1;
}

void ndpi_register_proto_maplestory (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_MAPLESTORY, "MapleStory", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_maplestory);
}
