/*
 * proto_quake.c
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

void ndpi_search_quake(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	if ((packet->payload_packet_len == 14
		 && get_u_int16_t(packet->payload, 0) == 0xffff && memcmp(&packet->payload[2], "getInfo", 7) == 0)
		|| (packet->payload_packet_len == 17
			&& get_u_int16_t(packet->payload, 0) == 0xffff && memcmp(&packet->payload[2], "challenge", 9) == 0)
		|| (packet->payload_packet_len > 20
			&& packet->payload_packet_len < 30
			&& get_u_int16_t(packet->payload, 0) == 0xffff && memcmp(&packet->payload[2], "getServers", 10) == 0)) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Quake IV detected.\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_QUAKE;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_QUAKE] = 1;
		return;
	}

	/* Quake III/Quake Live */
	if (packet->payload_packet_len == 15 && get_u_int32_t(packet->payload, 0) == 0xffffffff
		&& memcmp(&packet->payload[4], "getinfo", NDPI_STATICSTRING_LEN("getinfo")) == 0) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Quake III Arena/Quake Live detected.\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_QUAKE;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_QUAKE] = 1;
		return;
	}
	
	if (packet->payload_packet_len == 16 && get_u_int32_t(packet->payload, 0) == 0xffffffff
		&& memcmp(&packet->payload[4], "getchallenge", NDPI_STATICSTRING_LEN("getchallenge")) == 0) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Quake III Arena/Quake Live detected.\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_QUAKE;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_QUAKE] = 1;
		return;
	}
	
	if (packet->payload_packet_len > 20 && packet->payload_packet_len < 30
		&& get_u_int32_t(packet->payload, 0) == 0xffffffff
		&& memcmp(&packet->payload[4], "getservers", NDPI_STATICSTRING_LEN("getservers")) == 0) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Quake III Arena/Quake Live detected.\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_QUAKE;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_QUAKE] = 1;
		return;
	}

	/* ports for startup packet:
	   Quake I        26000 (starts with 0x8000)
	   Quake II       27910
	   Quake III      27960 (increases with each player)
	   Quake IV       27650
	   Quake World    27500
	   Quake Wars     ?????
	 */

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Quake excluded.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_QUAKE] = 1;
}

void ndpi_register_proto_quake (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_QUAKE, "Quake", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_quake);
}
