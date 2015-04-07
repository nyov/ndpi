/*
 * proto_ssh.c
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

void ndpi_search_ssh(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (flow->l4.tcp.ssh_stage == 0) {
		if (packet->payload_packet_len > 7 && packet->payload_packet_len < 100
			&& memcmp(packet->payload, "SSH-", 4) == 0) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "ssh stage 0 passed\n");
			flow->l4.tcp.ssh_stage = 1 + packet->packet_direction;
			return;
		}
	} else if (flow->l4.tcp.ssh_stage == (2 - packet->packet_direction)) {
		if (packet->payload_packet_len > 7 && packet->payload_packet_len < 100
			&& memcmp(packet->payload, "SSH-", 4) == 0) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found ssh\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_SSH;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_SSH] = 1;
			return;

		}


	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "excluding ssh at stage %d\n", flow->l4.tcp.ssh_stage);
	flow->ndpi_excluded_app[NDPI_RESULT_APP_SSH] = 1;
}

void ndpi_register_proto_ssh (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {22, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_SSH, "SSH", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_ssh);
}
