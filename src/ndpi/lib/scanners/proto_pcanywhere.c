/*
 * proto_pcanywhere.c
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

void ndpi_search_pcanywhere(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	if (packet->udp != NULL && packet->udp->dest == htons(5632)
		&& packet->payload_packet_len == 2
		&& (memcmp(packet->payload, "NQ", 2) == 0 || memcmp(packet->payload, "ST", 2) == 0)) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "PC Anywhere name or status query detected.\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_PCANYWHERE;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_PCANYWHERE] = 1;
		return;
	}

	flow->ndpi_excluded_app[NDPI_RESULT_APP_PCANYWHERE] = 1;
}

void ndpi_register_proto_pcanywhere (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_PCANYWHERE, "PcAnywhere", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_pcanywhere);
}
