/*
 * proto_dhcpv6.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */



/* include files */

#include "ndpi_protocols.h"

void ndpi_search_dhcpv6_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->payload_packet_len >= 4 &&
		(packet->udp->source == htons(546) || packet->udp->source == htons(547)) &&
		(packet->udp->dest == htons(546) || packet->udp->dest == htons(547)) &&
		packet->payload[0] >= 1 && packet->payload[0] <= 13) {

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "DHCPv6 detected.\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_DHCPV6;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_DHCPV6] = 1;
		return;
	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "DHCPv6 excluded.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_DHCPV6] = 1;
}

void ndpi_register_proto_dhcpv6 (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_DHCPV6, "DHCPv6", NDPI_SELECTION_BITMASK_PROTOCOL_V6_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_dhcpv6_udp);
}
