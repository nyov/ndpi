/*
 * proto_ipp.c
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

void ndpi_search_ipp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;

	u_int8_t i;

	NDPI_LOG(0_IPP, ndpi_struct, NDPI_LOG_DEBUG, "search ipp\n");
	if (packet->payload_packet_len > 20) {

		NDPI_LOG(0_IPP, ndpi_struct, NDPI_LOG_DEBUG, "searching for a payload with a pattern like 'number(1to8)blanknumber(1to3)ipp://.\n");
		/* this pattern means that there is a printer saying that his state is idle,
		 * means that he is not printing anything at the moment */
		i = 0;

		if (packet->payload[i] < '0' || packet->payload[i] > '9') {
			NDPI_LOG(0_IPP, ndpi_struct, NDPI_LOG_DEBUG, "payload does not begin with a number.\n");
			goto search_for_next_pattern;
		}

		for (;;) {
			i++;
			if (!((packet->payload[i] >= '0' && packet->payload[i] <= '9') ||
				  (packet->payload[i] >= 'a' && packet->payload[i] <= 'f') ||
				  (packet->payload[i] >= 'A' && packet->payload[i] <= 'F')) || i > 8) {
				NDPI_LOG(0_IPP, ndpi_struct, NDPI_LOG_DEBUG, "read symbols while the symbol is a number.\n");
				break;
			}
		}

		if (packet->payload[i++] != ' ') {
			NDPI_LOG(0_IPP, ndpi_struct, NDPI_LOG_DEBUG, "there is no blank following the number.\n");
			goto search_for_next_pattern;
		}

		if (packet->payload[i] < '0' || packet->payload[i] > '9') {
			NDPI_LOG(0_IPP, ndpi_struct, NDPI_LOG_DEBUG, "no number following the blank.\n");
			goto search_for_next_pattern;
		}

		for (;;) {
			i++;
			if (packet->payload[i] < '0' || packet->payload[i] > '9' || i > 12) {
				NDPI_LOG(0_IPP, ndpi_struct, NDPI_LOG_DEBUG, "read symbols while the symbol is a number.\n");
				break;
			}
		}

		if (memcmp(&packet->payload[i], " ipp://", 7) != 0) {
			NDPI_LOG(0_IPP, ndpi_struct, NDPI_LOG_DEBUG, "the string ' ipp://' does not follow.\n");
			goto search_for_next_pattern;
		}

		NDPI_LOG(0_IPP, ndpi_struct, NDPI_LOG_DEBUG, "found ipp\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_IPP;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_IPP] = 1;
		return;
	}

  search_for_next_pattern:

	if (packet->payload_packet_len > 3 && memcmp(packet->payload, "POST", 4) == 0) {
		ndpi_parse_packet_line_info(ndpi_struct, flow);
		
		if (packet->content_line.ptr != NULL && packet->content_line.len > 14 && memcmp(packet->content_line.ptr, "application/ipp", 15) == 0) {
			NDPI_LOG(0_IPP, ndpi_struct, NDPI_LOG_DEBUG, "found ipp via POST ... application/ipp.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_IPP;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_IPP] = 1;
			return;
		}
	}
	
	NDPI_LOG(0_IPP, ndpi_struct, NDPI_LOG_DEBUG, "no ipp detected.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_IPP] = 1;
}

void ndpi_register_proto_ipp (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_IPP, "IPP", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_ipp);
}
