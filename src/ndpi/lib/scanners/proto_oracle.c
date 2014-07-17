/*
 * proto_oracle.c
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

#include "ndpi_utils.h"
#include "ndpi_protocols.h"

void ndpi_search_oracle(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search for ORACLE.\n");

  if(packet->tcp != NULL) {
    sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "calculating ORACLE over tcp.\n");
    /* Oracle Database 9g,10g,11g */
    if ((dport == 1521 || sport == 1521)
	&&  (((packet->payload[0] == 0x07) && (packet->payload[1] == 0xff) && (packet->payload[2] == 0x00))
	     || ((packet->payload_packet_len >= 232) && ((packet->payload[0] == 0x00) || (packet->payload[0] == 0x01)) 
	     && (packet->payload[1] != 0x00)
	     && (packet->payload[2] == 0x00)
		 && (packet->payload[3] == 0x00)))) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found oracle.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_ORACLE;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_ORACLE] = 1;
    } else if (packet->payload_packet_len == 213 && packet->payload[0] == 0x00 &&
               packet->payload[1] == 0xd5 && packet->payload[2] == 0x00 &&
               packet->payload[3] == 0x00 ) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found oracle.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_ORACLE;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_ORACLE] = 1;
    }
  } else {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude ORACLE.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_ORACLE] = 1;
  }
}

void ndpi_register_proto_oracle (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {1521, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_ORACLE, "Oracle", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_oracle);
}
