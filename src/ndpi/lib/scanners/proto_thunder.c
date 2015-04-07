/*
 * proto_thunder.c
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
	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_int_search_thunder_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	   
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->payload_packet_len > 8 && packet->payload[0] >= 0x30 && packet->payload[0] < 0x40 && packet->payload[1] == 0 && packet->payload[2] == 0 && packet->payload[3] == 0) {
	  
		if (flow->thunder_stage == 3) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "THUNDER udp detected\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_THUNDER;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_THUNDER] = 1;
			return;
		}

		flow->thunder_stage++;
	
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe thunder udp packet detected, stage increased to %u\n", flow->thunder_stage);
		return;
	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "excluding thunder udp at stage %u\n", flow->thunder_stage);
	flow->ndpi_excluded_app[NDPI_RESULT_APP_THUNDER] = 1;
}

#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 void ndpi_int_search_thunder_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	   
	struct ndpi_packet_struct *packet = &flow->packet;
	
	if (packet->payload_packet_len > 8 && packet->payload[0] >= 0x30 && packet->payload[0] < 0x40 && packet->payload[1] == 0 && packet->payload[2] == 0 && packet->payload[3] == 0) {
	  
		if (flow->thunder_stage == 3) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "THUNDER tcp detected\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_THUNDER;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_THUNDER] = 1;
			return;
		}

		flow->thunder_stage++;
		
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe thunder tcp packet detected, stage increased to %u\n", flow->thunder_stage);
		
		return;
	}

	if (flow->thunder_stage == 0 && packet->payload_packet_len > 17 && memcmp(packet->payload, "POST / HTTP/1.1\r\n", 17) == 0) {
	  
		ndpi_parse_packet_line_info(ndpi_struct, flow);

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe thunder http POST packet detected, parsed packet lines: %u, empty line set %u (at: %u)\n",
			packet->parsed_lines, packet->empty_line_position_set, packet->empty_line_position);

		if (packet->empty_line_position_set != 0 && packet->content_line.ptr != NULL && packet->content_line.len == 24 &&
			memcmp(packet->content_line.ptr, "application/octet-stream", 24) == 0 && packet->empty_line_position_set < (packet->payload_packet_len - 8)
			&& packet->payload[packet->empty_line_position + 2] >= 0x30
			&& packet->payload[packet->empty_line_position + 2] < 0x40
			&& packet->payload[packet->empty_line_position + 3] == 0x00
			&& packet->payload[packet->empty_line_position + 4] == 0x00
			&& packet->payload[packet->empty_line_position + 5] == 0x00) {
		  
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe thunder http POST packet application does match\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_THUNDER;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_THUNDER] = 1;
		
			return;
		}
	}
	
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "excluding thunder tcp at stage %u\n", flow->thunder_stage);
	flow->ndpi_excluded_app[NDPI_RESULT_APP_THUNDER] = 1;
}

void ndpi_search_thunder(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->tcp != NULL) {
		ndpi_int_search_thunder_tcp(ndpi_struct, flow);
	} else if (packet->udp != NULL) {
		ndpi_int_search_thunder_udp(ndpi_struct, flow);
	}
}

void ndpi_register_proto_thunder (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_THUNDER, "Thunder", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_thunder);
}
