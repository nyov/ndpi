/*
 * proto_socrates.c
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

#include "ndpi_protocols.h"

void ndpi_search_socrates(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search socrates.\n");
	
	if (packet->udp != NULL) {
		if (packet->payload_packet_len > 9 && packet->payload[0] == 0xfe && packet->payload[packet->payload_packet_len - 1] == 0x05) {
		  
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found fe.\n");
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "len match.\n");
			
			if (memcmp(&packet->payload[2], "socrates", 8) == 0) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found socrates udp.\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_SOCRATES;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_SOCRATES] = 1;
			}

		}
	} else if (packet->tcp != NULL) {
		if (packet->payload_packet_len > 13 && packet->payload[0] == 0xfe && packet->payload[packet->payload_packet_len - 1] == 0x05) {
		  
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found fe.\n");
		
			if (packet->payload_packet_len == ntohl(get_u_int32_t(packet->payload, 2))) {
			  
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "len match.\n");
				
				if (memcmp(&packet->payload[6], "socrates", 8) == 0) {
					NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found socrates tcp.\n");
					flow->ndpi_result_app = NDPI_RESULT_APP_SOCRATES;
					flow->ndpi_excluded_app[NDPI_RESULT_APP_SOCRATES] = 1;
				}
			}
		}
	}
	
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude socrates.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_SOCRATES] = 1;
}

void ndpi_register_proto_socrates (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_SOCRATES, "Socrates", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_socrates);
}
