/*
 * proto_filetopia.c
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

void ndpi_search_filetopia(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	if (flow->l4.tcp.filetopia_stage == 0) {
		if (packet->payload_packet_len >= 50 && packet->payload_packet_len <= 70
			&& packet->payload[0] == 0x03 && packet->payload[1] == 0x9a
			&& packet->payload[3] == 0x22 && packet->payload[packet->payload_packet_len - 1] == 0x2b) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Filetopia stage 1 detected\n");
			flow->l4.tcp.filetopia_stage = 1;
			return;
		}

	} else if (flow->l4.tcp.filetopia_stage == 1) {
		if (packet->payload_packet_len >= 100 && packet->payload[0] == 0x03
			&& packet->payload[1] == 0x9a && (packet->payload[3] == 0x22 || packet->payload[3] == 0x23)) {

			int i;
			for (i = 0; i < 10; i++) {	// check 10 bytes for valid ASCII printable characters
				if (!(packet->payload[5 + i] >= 0x20 && packet->payload[5 + i] <= 0x7e)) {
					goto end_filetopia_nothing_found;
				}
			}

			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Filetopia stage 2 detected\n");
			flow->l4.tcp.filetopia_stage = 2;
			return;
		}


	} else if (flow->l4.tcp.filetopia_stage == 2) {
		if (packet->payload_packet_len >= 4 && packet->payload_packet_len <= 100
			&& packet->payload[0] == 0x03 && packet->payload[1] == 0x9a
			&& (packet->payload[3] == 0x22 || packet->payload[3] == 0x23)) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Filetopia detected\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_FILETOPIA;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_FILETOPIA] = 1;
			return;
		}

	}

  end_filetopia_nothing_found:
	flow->ndpi_excluded_app[NDPI_RESULT_APP_FILETOPIA] = 1;
}

void ndpi_register_proto_filetopia (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_FILETOPIA, "Filetopia", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_filetopia);
}
