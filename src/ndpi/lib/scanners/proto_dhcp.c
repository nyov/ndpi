/*
 * proto_dhcp.c
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

void ndpi_search_dhcp_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	/* this detection also works for asymmetric dhcp traffic */
	/* check standard DHCP 0.0.0.0:68 -> 255.255.255.255:67 */
	if (packet->payload_packet_len >= 244 && (packet->udp->source == htons(67)
											  || packet->udp->source == htons(68))
		&& (packet->udp->dest == htons(67) || packet->udp->dest == htons(68))
		&& get_u_int32_t(packet->payload, 236) == htonl(0x63825363)
		&& get_u_int16_t(packet->payload, 240) == htons(0x3501)) {

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "DHCP request\n");

		flow->ndpi_result_app = NDPI_RESULT_APP_DHCP;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_DHCP] = 1;
		return;
	}

	flow->ndpi_excluded_app[NDPI_RESULT_APP_DHCP] = 1;
}

void ndpi_register_proto_dhcp (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {67, 68, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_DHCP, "DHCP", NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_dhcp_udp);
}
