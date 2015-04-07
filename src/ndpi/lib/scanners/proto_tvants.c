/*
 * proto_tvants.c
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

void ndpi_search_tvants(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  
	struct ndpi_packet_struct *packet = &flow->packet;
	
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search tvants.  \n");

	if (packet->udp != NULL && packet->payload_packet_len > 57
		&& packet->payload[0] == 0x04 && packet->payload[1] == 0x00
		&& (packet->payload[2] == 0x05 || packet->payload[2] == 0x06
			|| packet->payload[2] == 0x07) && packet->payload[3] == 0x00
		&& packet->payload_packet_len == (packet->payload[5] << 8) + packet->payload[4]
		&& packet->payload[6] == 0x00 && packet->payload[7] == 0x00
		&& (memcmp(&packet->payload[48], "TVANTS", 6) == 0
			|| memcmp(&packet->payload[49], "TVANTS", 6) == 0 || memcmp(&packet->payload[51], "TVANTS", 6) == 0)) {

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found tvants over udp.  \n");
		flow->ndpi_result_app = NDPI_RESULT_APP_TVANTS;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_TVANTS] = 1;

	} else if (packet->tcp != NULL && packet->payload_packet_len > 15
			   && packet->payload[0] == 0x04 && packet->payload[1] == 0x00
			   && packet->payload[2] == 0x07 && packet->payload[3] == 0x00
			   && packet->payload_packet_len == (packet->payload[5] << 8) + packet->payload[4]
			   && packet->payload[6] == 0x00 && packet->payload[7] == 0x00
			   && memcmp(&packet->payload[8], "TVANTS", 6) == 0) {

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found tvants over tcp.  \n");
		flow->ndpi_result_app = NDPI_RESULT_APP_TVANTS;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_TVANTS] = 1;

	}
	
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude tvants.  \n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_TVANTS] = 1;

}

void ndpi_register_proto_tvants (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_TVANTS, "Tvants", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_tvants);
}
