/*
 * proto_ssdp.c
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

/* this detection also works asymmetrically */
void ndpi_search_ssdp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search ssdp.\n");
	
	if (packet->udp != NULL) {

		if (packet->payload_packet_len > 100) {
			if ((memcmp(packet->payload, "M-SEARCH * HTTP/1.1", 19) == 0)
				|| memcmp(packet->payload, "NOTIFY * HTTP/1.1", 17) == 0) {


				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found ssdp.\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_SSDP;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_SSDP] = 1;
				return;
			}

			#define SSDP_HTTP "HTTP/1.1 200 OK\r\n"
			if(memcmp(packet->payload, SSDP_HTTP, strlen(SSDP_HTTP)) == 0) {
			  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found ssdp.\n");
			  flow->ndpi_result_app = NDPI_RESULT_APP_SSDP;
			  flow->ndpi_excluded_app[NDPI_RESULT_APP_SSDP] = 1;
			  return;
			}
		}
	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "ssdp excluded.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_SSDP] = 1;
}

void ndpi_register_proto_ssdp (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_SSDP, "SSDP", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_ssdp);
}
