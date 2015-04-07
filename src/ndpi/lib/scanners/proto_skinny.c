/*
 * proto_skinny.c
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
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

void ndpi_search_skinny(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;
  const char pattern_9_bytes[9] = { 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  const char pattern_8_bytes[8] = { 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  const char keypadmsg_8_bytes[8] = { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  const char selectmsg_8_bytes[8] = { 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search for SKINNY.\n");

  if (packet->tcp != NULL) {
    sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "calculating SKINNY over tcp.\n");
    
    if (dport == 2000  && ((packet->payload_packet_len == 24 && memcmp(&packet->payload[0], keypadmsg_8_bytes, 8) == 0) 
	  || ((packet->payload_packet_len == 64) && memcmp(&packet->payload[0], pattern_8_bytes, 8) == 0))) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found skinny.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_SKINNY;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_SKINNY] = 1;
    } else if (sport == 2000 && ((packet->payload_packet_len == 28 && memcmp(&packet->payload[0], selectmsg_8_bytes, 8) == 0 ) ||
	  (packet->payload_packet_len == 44 && memcmp(&packet->payload[0], pattern_9_bytes, 9) == 0))) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found skinny.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_SKINNY;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_SKINNY] = 1;
    }
  } else {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude SKINNY.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_SKINNY] = 1;
  }
}

void ndpi_register_proto_skinny (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {2000, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_SKINNY, "CiscoSkinny", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_skinny);
}
