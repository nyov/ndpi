/*
 * proto_ldap.c
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

void ndpi_search_ldap(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search ldap\n");


	if (packet->payload_packet_len >= 14 && packet->payload[0] == 0x30) {

		// simple type
		if (packet->payload[1] == 0x0c && packet->payload_packet_len == 14 &&
			packet->payload[packet->payload_packet_len - 1] == 0x00 && packet->payload[2] == 0x02) {

			if (packet->payload[3] == 0x01 &&
				(packet->payload[5] == 0x60 || packet->payload[5] == 0x61) && packet->payload[6] == 0x07) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found ldap simple type 1\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_LDAP;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_LDAP] = 1;
				return;
			}

			if (packet->payload[3] == 0x02 &&
				(packet->payload[6] == 0x60 || packet->payload[6] == 0x61) && packet->payload[7] == 0x07) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found ldap simple type 2\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_LDAP;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_LDAP] = 1;
				return;
			}
		}
		
		// normal type
		if (packet->payload[1] == 0x84 && packet->payload_packet_len >= 0x84 &&
			packet->payload[2] == 0x00 && packet->payload[3] == 0x00 && packet->payload[6] == 0x02) {

			if (packet->payload[7] == 0x01 &&
				(packet->payload[9] == 0x60 || packet->payload[9] == 0x61 || packet->payload[9] == 0x63 ||
				 packet->payload[9] == 0x64) && packet->payload[10] == 0x84) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found ldap type 1\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_LDAP;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_LDAP] = 1;
				return;
			}

			if (packet->payload[7] == 0x02 &&
				(packet->payload[10] == 0x60 || packet->payload[10] == 0x61 || packet->payload[10] == 0x63 ||
				 packet->payload[10] == 0x64) && packet->payload[11] == 0x84) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found ldap type 2\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_LDAP;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_LDAP] = 1;
				return;
			}
		}
	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "ldap excluded.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_LDAP] = 1;
}

void ndpi_register_proto_ldap (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {389, 0, 0, 0, 0};
  int udp_ports[5] = {389, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_LDAP, "LDAP", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_ldap);
}
