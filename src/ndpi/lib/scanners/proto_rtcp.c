/*
 * proto_rtcp.c (RTP Control Protocol)
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
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

void ndpi_search_rtcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search for RTCP.\n");

  if (packet->tcp != NULL) {
    sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "calculating dport over tcp.\n");

    if(packet->payload_packet_len > 13 && (sport == 554 || dport == 554) &&
       packet->payload[0] == 0x00 && packet->payload[1] == 0x00 &&
       packet->payload[2] == 0x01 && packet->payload[3] == 0x01 &&
       packet->payload[4] == 0x08 && packet->payload[5] == 0x0a &&
       packet->payload[6] == 0x00 && packet->payload[7] == 0x01) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found rtcp.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_RTCP;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_RTCP] = 1;
    }
  } else if (packet->udp != NULL) {
    sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "calculating dport over udp.\n");
    if(((packet->payload_packet_len >= 28 || packet->payload_packet_len <= 1200) &&
	((packet->payload[0] == 0x80) && ((packet->payload[1] == 0xc8) || (packet->payload[1] == 0xc9)) && (packet->payload[2] == 0x00)))
       || (((packet->payload[0] == 0x81) && ((packet->payload[1] == 0xc8) || (packet->payload[1] == 0xc9))
	    && (packet->payload[2] == 0x00)))) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found rtcp.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_RTCP;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_RTCP] = 1;
    }
  } else {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude RTCP.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_RTCP] = 1;
  }
}

void ndpi_register_proto_rtcp (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_RTCP, "RTCP", NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_rtcp);
}
