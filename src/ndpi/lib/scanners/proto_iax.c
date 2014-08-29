/*
 * proto_iax.c
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

void ndpi_search_iax(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  
  struct ndpi_packet_struct *packet = &flow->packet;

  if (!packet->udp) {
    return;
  }
  
  u_int8_t i;
  u_int16_t packet_len;

  if (						/* 1. iax is udp based, port 4569 */
      (packet->udp->source == htons(4569) || packet->udp->dest == htons(4569))
      /* check for iax new packet */
      && packet->payload_packet_len >= 12
      /* check for dst call id == 0, do not check for highest bit (packet retransmission) */
      // && (ntohs(get_u_int16_t(packet->payload, 2)) & 0x7FFF) == 0
      /* check full IAX packet  */
      && (packet->payload[0] & 0x80) != 0
      /* outbound seq == 0 */
      && packet->payload[8] == 0
      /* inbound seq == 0 || 1  */
      && (packet->payload[9] == 0 || packet->payload[9] == 0x01)
      /*  */
      && packet->payload[10] == 0x06
      /* IAX type: 0-15 */
      && packet->payload[11] <= 15) {

    if (packet->payload_packet_len == 12) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found IAX.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_IAX;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_IAX] = 1;
      return;
    }
    
    packet_len = 12;
    
    for (i = 0; i < 15; i++) {
      packet_len = packet_len + 2 + packet->payload[packet_len + 1];
      
      if (packet_len == packet->payload_packet_len) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found IAX.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_IAX;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_IAX] = 1;
	return;
      }
      
      if (packet_len > packet->payload_packet_len) {
	break;
      }
    }

  }

  flow->ndpi_excluded_app[NDPI_RESULT_APP_IAX] = 1;
}

void ndpi_register_proto_iax (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {4569, 0, 0, 0, 0};
  int udp_ports[5] = {4569, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_IAX, "IAX", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_iax);
}
