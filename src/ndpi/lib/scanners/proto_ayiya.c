/*
 * proto_ayiya.c
 *
 * Copyright (C) 2011-14 - ntop.org
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

/*
  http://en.wikipedia.org/wiki/Anything_In_Anything 
  http://tools.ietf.org/html/rfc4891
*/


#include "ndpi_protocols.h"

struct ayiya {
  u_int8_t flags[3];
  u_int8_t next_header;
  u_int32_t epoch;
  u_int8_t identity[16];
  u_int8_t signature[20];  
};

void ndpi_search_ayiya(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  if (packet->udp) {
    
    /* Ayiya is udp based, port 5072 */
    if ((packet->udp->source == htons(5072) || packet->udp->dest == htons(5072))
	/* check for ayiya new packet */
	&& (packet->payload_packet_len > 44)
	) {
      /* FINISH */
      struct ayiya *a = (struct ayiya*)packet->payload;
      u_int32_t epoch = ntohl(a->epoch), now;
      u_int32_t fireyears = 86400 * 365 * 5;
    
      #ifndef __KERNEL__
	now = time(NULL);
      #else
	now = 1402729042; /* Dummy workaround */
      #endif
      
      if ((epoch >= (now - fireyears)) && (epoch <= (now+86400 /* 1 day */))) {
	flow->ndpi_result_app = NDPI_RESULT_APP_AYIYA;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_AYIYA] = 1;
      }

      return;
    }

    flow->ndpi_excluded_app[NDPI_RESULT_APP_AYIYA] = 1;
  }
}

void ndpi_register_proto_ayiya (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {5072, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_AYIYA, "Ayiya", NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_ayiya);
}
