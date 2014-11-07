/*
 * proto_xbox.c
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

void ndpi_search_xbox(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  
	struct ndpi_packet_struct *packet = &flow->packet;
	
	/* Break after 20 packets. */
	if (flow->packet_counter > 20) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude Xbox.\n");
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_XBOX] = 1;
	  return;
	}

	/* this detection also works for asymmetric xbox udp traffic */
	if (packet->udp != NULL) {

		u_int16_t dport = ntohs(packet->udp->dest);
		u_int16_t sport = ntohs(packet->udp->source);

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search xbox\n");

		if (packet->payload_packet_len > 12 && get_u_int32_t(packet->payload, 0) == 0 && packet->payload[5] == 0x58 &&
			memcmp(&packet->payload[7], "\x00\x00\x00", 3) == 0) {

			if ((packet->payload[4] == 0x0c && packet->payload[6] == 0x76) ||
				(packet->payload[4] == 0x02 && packet->payload[6] == 0x18) ||
				(packet->payload[4] == 0x0b && packet->payload[6] == 0x80) ||
				(packet->payload[4] == 0x03 && packet->payload[6] == 0x40) ||
				(packet->payload[4] == 0x06 && packet->payload[6] == 0x4e)) {

				flow->ndpi_result_app = NDPI_RESULT_APP_XBOX;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_XBOX] = 1;
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "xbox udp connection detected\n");
				return;
			}
		}
		
		if ((dport == 3074 || sport == 3074)
			&& ((packet->payload_packet_len == 24 && packet->payload[0] == 0x00)
				|| (packet->payload_packet_len == 42 && packet->payload[0] == 0x4f && packet->payload[2] == 0x0a)
				|| (packet->payload_packet_len == 80 && ntohs(get_u_int16_t(packet->payload, 0)) == 0x50bc
					&& packet->payload[2] == 0x45)
				|| (packet->payload_packet_len == 40 && ntohl(get_u_int32_t(packet->payload, 0)) == 0xcf5f3202)
				|| (packet->payload_packet_len == 38 && ntohl(get_u_int32_t(packet->payload, 0)) == 0xc1457f03)
				|| (packet->payload_packet_len == 28 && ntohl(get_u_int32_t(packet->payload, 0)) == 0x015f2c00))) {
		  
			if (flow->l4.udp.xbox_stage == 1) {
				flow->ndpi_result_app = NDPI_RESULT_APP_XBOX;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_XBOX] = 1;
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "xbox udp connection detected\n");
				return;
			}
			
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe xbox.\n");
			flow->l4.udp.xbox_stage++;
			return;
		}

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "xbox udp excluded.\n");
		flow->ndpi_excluded_app[NDPI_RESULT_APP_XBOX] = 1;
	} else if (packet->user_agent_line.ptr != NULL && packet->user_agent_line.len >= 17 && memcmp(packet->user_agent_line.ptr, "Xbox Live Client/", 17) == 0) {
	    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Xbox detected\n");
	    flow->ndpi_result_app = NDPI_RESULT_APP_XBOX;
	    flow->ndpi_excluded_app[NDPI_RESULT_APP_XBOX] = 1;
	}
}

void ndpi_register_proto_xbox (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_XBOX, "Xbox", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_xbox);
}
