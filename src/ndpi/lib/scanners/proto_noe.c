/*
 * proto_noe.c
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
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

/*  (Alcatel new office environment) */

#include "ndpi_api.h"

void ndpi_search_noe(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search for NOE.\n");
  
  if (packet->udp != NULL) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "calculating dport over udp.\n");

    if (packet->payload_packet_len == 1 && ( packet->payload[0] == 0x05 || packet->payload[0] == 0x04 )) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found noe.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_NOE;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_NOE] = 1;
      return;
    } else if((packet->payload_packet_len == 5 || packet->payload_packet_len == 12) &&
	      (packet->payload[0] == 0x07 ) && 
	      (packet->payload[1] == 0x00 ) &&
	      (packet->payload[2] != 0x00 ) &&
	      (packet->payload[3] == 0x00 )) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found noe.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_NOE;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_NOE] = 1;
    } else if((packet->payload_packet_len >= 25) &&
	      (packet->payload[0] == 0x00 &&
	       packet->payload[1] == 0x06 &&
	       packet->payload[2] == 0x62 &&
	       packet->payload[3] == 0x6c)) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found noe.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_NOE;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_NOE] = 1;
    }
  } else {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude NOE.\n");
      flow->ndpi_excluded_app[NDPI_RESULT_APP_NOE] = 1;
    }
}

void ndpi_register_proto_noe (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_NOE, "NOE", NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_noe);
}
