/*
 * proto_telnet.c
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

#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 u_int8_t search_iac(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	u_int16_t a;

	if (packet->payload_packet_len < 3) {
		return 0;
	}

	if (!(packet->payload[0] == 0xff
		  && packet->payload[1] > 0xf9 && packet->payload[1] != 0xff && packet->payload[2] < 0x28)) {
		return 0;
	}

	a = 3;

	while (a < packet->payload_packet_len - 2) {
		// commands start with a 0xff byte followed by a command byte >= 0xf0 and < 0xff
		// command bytes 0xfb to 0xfe are followed by an option byte <= 0x28
		if (!(packet->payload[a] != 0xff ||
			  (packet->payload[a] == 0xff && (packet->payload[a + 1] >= 0xf0) && (packet->payload[a + 1] <= 0xfa)) ||
			  (packet->payload[a] == 0xff && (packet->payload[a + 1] >= 0xfb) && (packet->payload[a + 1] != 0xff)
			   && (packet->payload[a + 2] <= 0x28)))) {
			return 0;
		}
		a++;
	}

	return 1;
}

/* this detection also works asymmetrically */
void ndpi_search_telnet_tcp(struct ndpi_detection_module_struct
							  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search telnet.\n");

	if (search_iac(ndpi_struct, flow) == 1) {

		if (flow->l4.tcp.telnet_stage == 2) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "telnet identified.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_TELNET;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_TELNET] = 1;
			return;
		}
		flow->l4.tcp.telnet_stage++;
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "telnet stage %u.\n", flow->l4.tcp.telnet_stage);
		return;
	}

	if ((flow->packet_counter < 12 && flow->l4.tcp.telnet_stage > 0) || flow->packet_counter < 6) {
		return;
	} else {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "telnet excluded.\n");
		flow->ndpi_excluded_app[NDPI_RESULT_APP_TELNET] = 1;
	}
	return;
}

void ndpi_register_proto_telnet (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {23, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_TELNET, "Telnet", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_telnet_tcp);
}
