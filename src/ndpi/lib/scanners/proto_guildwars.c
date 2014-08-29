/*
 * proto_guildwars.c
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

void ndpi_search_guildwars(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search guildwars.\n");

	if (packet->payload_packet_len == 64 && get_u_int16_t(packet->payload, 1) == ntohs(0x050c)
		&& memcmp(&packet->payload[50], "@2&P", 4) == 0) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "GuildWars version 29.350: found.\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_GUILDWARS;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_GUILDWARS] = 1;
		return;
	}
	
	if (packet->payload_packet_len == 16 && get_u_int16_t(packet->payload, 1) == ntohs(0x040c)
		&& get_u_int16_t(packet->payload, 4) == ntohs(0xa672)
		&& packet->payload[8] == 0x01 && packet->payload[12] == 0x04) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "GuildWars version 29.350: found.\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_GUILDWARS;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_GUILDWARS] = 1;
		return;
	}
	
	if (packet->payload_packet_len == 21 && get_u_int16_t(packet->payload, 0) == ntohs(0x0100)
		&& get_u_int32_t(packet->payload, 5) == ntohl(0xf1001000)
		&& packet->payload[9] == 0x01) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "GuildWars version 216.107.245.50: found.\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_GUILDWARS;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_GUILDWARS] = 1;
		return;
	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude guildwars.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_GUILDWARS] = 1;
}

void ndpi_register_proto_guildwars (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_GUILDWARS, "Guildwars", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_guildwars);
}
