/*
 * proto_xdmcp.c
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

void ndpi_search_xdmcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search xdmcp.\n");

	if (packet->tcp != NULL && (ntohs(packet->tcp->dest) >= 6000 && ntohs(packet->tcp->dest) <= 6005)
		&& packet->payload_packet_len == 48
		&& packet->payload[0] == 0x6c && packet->payload[1] == 0x00
		&& ntohs(get_u_int16_t(packet->payload, 6)) == 0x1200 && ntohs(get_u_int16_t(packet->payload, 8)) == 0x1000) {

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found xdmcp over tcp.\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_XDMCP;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_XDMCP] = 1;
		return;
	}
	
	if (packet->udp != NULL && ntohs(packet->udp->dest) == 177
		&& packet->payload_packet_len >= 6 && packet->payload_packet_len == 6 + ntohs(get_u_int16_t(packet->payload, 4))
		&& ntohs(get_u_int16_t(packet->payload, 0)) == 0x0001 && ntohs(get_u_int16_t(packet->payload, 2)) == 0x0002) {

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found xdmcp over udp.\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_XDMCP;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_XDMCP] = 1;
		return;
	}


	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude xdmcp.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_XDMCP] = 1;
}

void ndpi_register_proto_xdmcp (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {177, 0, 0, 0, 0};
  int udp_ports[5] = {177, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_XDMCP, "XDMCP", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_xdmcp);
}
