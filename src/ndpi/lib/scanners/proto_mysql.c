/*
 * proto_mysql.c
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

void ndpi_search_mysql(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	if (packet->payload_packet_len > 37	//min length
		&& get_u_int16_t(packet->payload, 0) == packet->payload_packet_len - 4	//first 3 bytes are length
		&& get_u_int8_t(packet->payload, 2) == 0x00	//3rd byte of packet length
		&& get_u_int8_t(packet->payload, 3) == 0x00	//packet sequence number is 0 for startup packet
		&& get_u_int8_t(packet->payload, 5) > 0x30	//server version > 0
		&& get_u_int8_t(packet->payload, 5) < 0x37	//server version < 7
		&& get_u_int8_t(packet->payload, 6) == 0x2e	//dot
		) {
		u_int32_t a;
	
		for (a = 7; a + 31 < packet->payload_packet_len; a++) {
			if (packet->payload[a] == 0x00) {
				if (get_u_int8_t(packet->payload, a + 13) == 0x00	//filler byte
					&& get_u_int64_t(packet->payload, a + 19) == 0x0ULL	//13 more
					&& get_u_int32_t(packet->payload, a + 27) == 0x0	//filler bytes
					&& get_u_int8_t(packet->payload, a + 31) == 0x0) {
					NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "MySQL detected.\n");
					flow->ndpi_result_app = NDPI_RESULT_APP_MYSQL;
					flow->ndpi_excluded_app[NDPI_RESULT_APP_MYSQL] = 1;
					return;
				}
				break;
			}
		}
	}

	flow->ndpi_excluded_app[NDPI_RESULT_APP_MYSQL] = 1;
}

void ndpi_register_proto_mysql (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {3306, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_MYSQL, "MySQL", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_mysql);
}
