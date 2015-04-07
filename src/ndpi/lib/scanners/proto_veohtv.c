/*
 * proto_veohtv.c
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

void ndpi_search_veohtv(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  
	struct ndpi_packet_struct *packet = &flow->packet;

	if (flow->l4.tcp.veoh_tv_stage == 1 || flow->l4.tcp.veoh_tv_stage == 2) {
		if (packet->packet_direction != flow->setup_packet_direction &&
			packet->payload_packet_len > NDPI_STATICSTRING_LEN("HTTP/1.1 20")
			&& memcmp(packet->payload, "HTTP/1.1 ", NDPI_STATICSTRING_LEN("HTTP/1.1 ")) == 0 &&
			(packet->payload[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] == '2' ||
			 packet->payload[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] == '3' ||
			 packet->payload[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] == '4' ||
			 packet->payload[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] == '5')) {
		  
			if (flow->l4.tcp.veoh_tv_stage == 2) {
				flow->ndpi_excluded_app[NDPI_RESULT_APP_VEOHTV] = 1;
				return;
			}
			
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "VeohTV detected.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_VEOHTV;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_VEOHTV] = 1;
			return;
			
		} else if (flow->packet_direction_counter[(flow->setup_packet_direction == 1) ? 0 : 1] > 3) {
			if (flow->l4.tcp.veoh_tv_stage == 2) {
				flow->ndpi_excluded_app[NDPI_RESULT_APP_VEOHTV] = 1;
				return;
			}
			
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "VeohTV detected.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_VEOHTV;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_VEOHTV] = 1;
			return;
		} else {
			if (flow->packet_counter > 10) {
				if (flow->l4.tcp.veoh_tv_stage == 2) {
					flow->ndpi_excluded_app[NDPI_RESULT_APP_VEOHTV] = 1;
					return;
				}
				
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "VeohTV detected.\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_VEOHTV;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_VEOHTV] = 1;
				return;
			}
			
			return;
		}
	} else if (packet->udp) {
		/* UDP packets from Veoh Client Player
		 *
		 * packet starts with 16 byte random? value
		 * then a 4 byte mode value
		 *   values between 21 and 26 has been seen 
		 * then a 4 byte counter */

		if (packet->payload_packet_len == 28 &&
			get_u_int32_t(packet->payload, 16) == htonl(0x00000021) &&
			get_u_int32_t(packet->payload, 20) == htonl(0x00000000) && get_u_int32_t(packet->payload, 24) == htonl(0x01040000)) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "UDP VeohTV found.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_VEOHTV;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_VEOHTV] = 1;
			return;
		}
	}

	flow->ndpi_excluded_app[NDPI_RESULT_APP_VEOHTV] = 1;
}

void ndpi_register_proto_veohtv (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_VEOHTV, "VeohTV", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_veohtv);
}
