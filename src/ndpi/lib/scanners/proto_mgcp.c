/*
 * proto_mgcp.c
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
	 void ndpi_search_mgcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {

	struct ndpi_packet_struct *packet = &flow->packet;
	
	// information about MGCP taken from http://en.wikipedia.org/wiki/MGCP

	u_int16_t pos = 4;

	if (packet->payload_packet_len < 8) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude MGCP.\n");
		flow->ndpi_excluded_app[NDPI_RESULT_APP_MGCP] = 1;
		return;
	}

	// packet must end with 0x0d0a or with 0x0a
	if (packet->payload[packet->payload_packet_len - 1] != 0x0a && get_u_int16_t(packet->payload, packet->payload_packet_len - 2) != htons(0x0d0a)) {
	  
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude MGCP.\n");
		flow->ndpi_excluded_app[NDPI_RESULT_APP_MGCP] = 1;
		return;
	}

	if (packet->payload[0] != 'A' && packet->payload[0] != 'C' && packet->payload[0] != 'D' &&
		packet->payload[0] != 'E' && packet->payload[0] != 'M' && packet->payload[0] != 'N' && packet->payload[0] != 'R') {
	  
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude MGCP.\n");
		flow->ndpi_excluded_app[NDPI_RESULT_APP_MGCP] = 1;
		return;
	}
	
	if (memcmp(packet->payload, "AUEP ", 5) != 0 && memcmp(packet->payload, "AUCX ", 5) != 0 &&
		memcmp(packet->payload, "CRCX ", 5) != 0 && memcmp(packet->payload, "DLCX ", 5) != 0 &&
		memcmp(packet->payload, "EPCF ", 5) != 0 && memcmp(packet->payload, "MDCX ", 5) != 0 &&
		memcmp(packet->payload, "NTFY ", 5) != 0 && memcmp(packet->payload, "RQNT ", 5) != 0 && memcmp(packet->payload, "RSIP ", 5) != 0) {
	  
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude MGCP.\n");
		flow->ndpi_excluded_app[NDPI_RESULT_APP_MGCP] = 1;
		return;
	}
	
	// now search for string "MGCP " in the rest of the message
	while ((pos + 5) < packet->payload_packet_len) {
	  
		if (memcmp(&packet->payload[pos], "MGCP ", 5) == 0) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "MGCP match.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_MGCP;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_MGCP] = 1;
			return;
		}
		
		pos++;
	}
}

void ndpi_register_proto_mgcp (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_MGCP, "MGCP", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_mgcp);
}
