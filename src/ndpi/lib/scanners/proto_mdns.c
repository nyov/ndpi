/*
 * proto_mdns.c
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

#define NDPI_MAX_MDNS_REQUESTS                        128

static int ndpi_int_check_mdns_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  
	struct ndpi_packet_struct *packet = &flow->packet;

	if ((packet->payload[2] & 0x80) == 0 &&
		ntohs(get_u_int16_t(packet->payload, 4)) <= NDPI_MAX_MDNS_REQUESTS &&
		ntohs(get_u_int16_t(packet->payload, 6)) <= NDPI_MAX_MDNS_REQUESTS) {

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found MDNS with question query.\n");

		return 1;
	} else if ((packet->payload[2] & 0x80) != 0 &&
			   ntohs(get_u_int16_t(packet->payload, 4)) == 0 &&
			   ntohs(get_u_int16_t(packet->payload, 6)) <= NDPI_MAX_MDNS_REQUESTS &&
			   ntohs(get_u_int16_t(packet->payload, 6)) != 0) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found MDNS with answer query.\n");

		return 1;
	}

	return 0;
}

void ndpi_search_mdns(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	u_int16_t dport;
	
	/* check if UDP and */
	if (packet->udp != NULL) {
		/*read destination port */
		dport = ntohs(packet->udp->dest);

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "MDNS udp start \n");

		/*check standard MDNS to port 5353 */
		/*took this information from http://www.it-administrator.de/lexikon/multicast-dns.html */

		if (dport == 5353 && packet->payload_packet_len >= 12) {

			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found MDNS with destination port 5353\n");

			/* MDNS header is similar to dns header */
			/* dns header
			   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
			   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			   |                      ID                       |
			   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			   |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
			   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			   |                    QDCOUNT                    |
			   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			   |                    ANCOUNT                    |
			   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			   |                    NSCOUNT                    |
			   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			   |                    ARCOUNT                    |
			   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			   *
			   * dns query check: query: QR set, ancount = 0, nscount = 0, QDCOUNT < MAX_MDNS, ARCOUNT < MAX_MDNS
			   *
			 */

			/* mdns protocol must have destination address  224.0.0.251 */
			/* took this information from http://www.it-administrator.de/lexikon/multicast-dns.html */

			if (packet->iph != NULL && ntohl(packet->iph->daddr) == 0xe00000fb) {

				NDPI_LOG(0, ndpi_struct,
						NDPI_LOG_DEBUG, "found MDNS with destination address 224.0.0.251 (=0xe00000fb)\n");

				if (ndpi_int_check_mdns_payload(ndpi_struct, flow) == 1) {
					flow->ndpi_result_app = NDPI_RESULT_APP_MDNS;
					flow->ndpi_excluded_app[NDPI_RESULT_APP_MDNS] = 1;
					return;
				}
			}
			
			if (packet->iphv6 != NULL) {
				const u_int32_t *daddr = packet->iphv6->daddr.ndpi_v6_u.u6_addr32;
				if (daddr[0] == htonl(0xff020000) && daddr[1] == 0 && daddr[2] == 0 && daddr[3] == htonl(0xfb)) {

					NDPI_LOG(0, ndpi_struct,
							NDPI_LOG_DEBUG, "found MDNS with destination address ff02::fb\n");

					if (ndpi_int_check_mdns_payload(ndpi_struct, flow) == 1) {
						flow->ndpi_result_app = NDPI_RESULT_APP_MDNS;
						flow->ndpi_excluded_app[NDPI_RESULT_APP_MDNS] = 1;
						return;
					}
				}
			}
		}
	}
	
	flow->ndpi_excluded_app[NDPI_RESULT_APP_MDNS] = 1;
}

void ndpi_register_proto_mdns (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {5353, 5354, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_MDNS, "MDNS", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_mdns);
}
