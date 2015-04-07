/*
 * proto_ppstream.c
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

void ndpi_search_ppstream(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	/* check TCP Connections -> Videodata */
	if (packet->tcp != NULL) {
		if (packet->payload_packet_len >= 60 && get_u_int32_t(packet->payload, 52) == 0
			&& memcmp(packet->payload, "PSProtocol\x0", 11) == 0) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found ppstream over tcp.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_PPSTREAM;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_PPSTREAM] = 1;
			return;
		}
	}

	if (packet->udp != NULL) {
		if (packet->payload_packet_len > 2 && packet->payload[2] == 0x43
			&& ((packet->payload_packet_len - 4 == get_l16(packet->payload, 0))
				|| (packet->payload_packet_len == get_l16(packet->payload, 0))
				|| (packet->payload_packet_len >= 6 && packet->payload_packet_len - 6 == get_l16(packet->payload, 0)))) {
			flow->l4.udp.ppstream_stage++;
			if (flow->l4.udp.ppstream_stage == 5) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found ppstream over udp pattern len, 43.\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_PPSTREAM;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_PPSTREAM] = 1;
				return;
			}
			return;
		}

		if (flow->l4.udp.ppstream_stage == 0
			&& packet->payload_packet_len > 4 && ((packet->payload_packet_len - 4 == get_l16(packet->payload, 0))
			|| (packet->payload_packet_len == get_l16(packet->payload, 0))
			|| (packet->payload_packet_len >= 6
			&& packet->payload_packet_len - 6 == get_l16(packet->payload, 0)))) {

			if (packet->payload[2] == 0x00 && packet->payload[3] == 0x00 && packet->payload[4] == 0x03) {
				flow->l4.udp.ppstream_stage = 7;
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "need next packet I.\n");
				return;
			}
		}

		if (flow->l4.udp.ppstream_stage == 7
			&& packet->payload_packet_len > 4 && packet->payload[3] == 0x00
			&& ((packet->payload_packet_len - 4 == get_l16(packet->payload, 0))
				|| (packet->payload_packet_len == get_l16(packet->payload, 0))
				|| (packet->payload_packet_len >= 6 && packet->payload_packet_len - 6 == get_l16(packet->payload, 0)))
			&& (packet->payload[2] == 0x00 && packet->payload[4] == 0x03)) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found ppstream over udp with pattern Vb.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_PPSTREAM;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_PPSTREAM] = 1;
			return;
		}

	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude ppstream.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_PPSTREAM] = 1;
}

void ndpi_register_proto_ppstream (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_PPSTREAM, "PPStream", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_ppstream);
}
