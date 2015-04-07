/*
 * proto_h323.c
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

void ndpi_search_h323(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search H323.\n");

  if (packet->tcp != NULL) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "calculated dport over tcp.\n");

    /* H323  */
    if (packet->payload[0] == 0x03 && packet->payload[1] == 0x00 && packet->payload[2] == 0x00)
      {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found H323 broadcast.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_H323;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_H323] = 1;
	return;
      }
  }

  if (packet->udp != NULL) {
    sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "calculated dport over udp.\n");

    if(packet->payload[0] == 0x80 && packet->payload[1] == 0x08 && (packet->payload[2] == 0xe7 || packet->payload[2] == 0x26) &&
       packet->payload[4] == 0x00 && packet->payload[5] == 0x00) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found H323 broadcast.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_H323;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_H323] = 1;
	return;
      }
      
    /* H323  */
    if (sport == 1719 || dport == 1719) {
        if (packet->payload[0] == 0x16 && packet->payload[1] == 0x80 && packet->payload[4] == 0x06 && packet->payload[5] == 0x00) {
	    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found H323 broadcast.\n");
	    flow->ndpi_result_app = NDPI_RESULT_APP_H323;
	    flow->ndpi_excluded_app[NDPI_RESULT_APP_H323] = 1;
	    return;
	  } else if(packet->payload_packet_len >= 20 || packet->payload_packet_len <= 117) {
	    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found H323 broadcast.\n");
	    flow->ndpi_result_app = NDPI_RESULT_APP_H323;
	    flow->ndpi_excluded_app[NDPI_RESULT_APP_H323] = 1;
	    return;
	  } else {
	    flow->ndpi_excluded_app[NDPI_RESULT_APP_H323] = 1;
	    return;
	  }
      }
  }
}

void ndpi_register_proto_h323 (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {1719, 1720, 3478, 0, 0};
  int udp_ports[5] = {1719, 1720, 3478, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_H323, "H323", NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_h323);
}
