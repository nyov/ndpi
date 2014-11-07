/*
 * proto_fasttrack.c
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

void ndpi_search_fasttrack_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->payload_packet_len > 6 && ntohs(get_u_int16_t(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "detected 0d0a at the end of the packet.\n");

		if (memcmp(packet->payload, "GIVE ", 5) == 0 && packet->payload_packet_len >= 8) {
			u_int16_t i;
			for (i = 5; i < (packet->payload_packet_len - 2); i++) {
				// make shure that the argument to GIVE is numeric
				if (!(packet->payload[i] >= '0' && packet->payload[i] <= '9')) {
					goto exclude_fasttrack;
				}
			}

			NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "FASTTRACK GIVE DETECTED\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_FASTTRACK;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_FASTTRACK] = 1;
			return;
		}

		if (packet->payload_packet_len > 50 && memcmp(packet->payload, "GET /", 5) == 0) {
			u_int8_t a = 0;
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "detected GET /. \n");
			ndpi_parse_packet_line_info(ndpi_struct, flow);
			for (a = 0; a < packet->parsed_lines; a++) {
				if ((packet->line[a].len > 17 && memcmp(packet->line[a].ptr, "X-Kazaa-Username: ", 18) == 0)
					|| (packet->line[a].len > 23 && memcmp(packet->line[a].ptr, "User-Agent: PeerEnabler/", 24) == 0)) {
					NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "detected X-Kazaa-Username: || User-Agent: PeerEnabler/\n");
					flow->ndpi_result_app = NDPI_RESULT_APP_FASTTRACK;
					flow->ndpi_excluded_app[NDPI_RESULT_APP_FASTTRACK] = 1;
					return;
				}
			}
		}
	}

  exclude_fasttrack:
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "fasttrack/kazaa excluded.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_FASTTRACK] = 1;
}

void ndpi_register_proto_fasttrack (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_FASTTRACK, "FastTrack", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_fasttrack_tcp);
}
