/*
 * proto_radius.c
 *
 * Copyright (C) 2012-13 - ntop.org
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

struct radius_header {
  u_int8_t code;
  u_int8_t packet_id;
  u_int16_t len;
};

void ndpi_search_radius(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "radius detection...\n");

  struct ndpi_packet_struct *packet = &flow->packet;  
  u_int32_t payload_len = packet->payload_packet_len;

  if (packet->udp != NULL) {
    struct radius_header *h = (struct radius_header*)packet->payload;
    u_int len = ntohs(h->len);

    if ((payload_len > sizeof(struct radius_header))
       && (h->code > 0)
       && (h->code <= 5)
       && (len == payload_len)) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found radius.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_RADIUS;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_RADIUS] = 1;	
      
      return;
    }
    
    flow->ndpi_excluded_app[NDPI_RESULT_APP_RADIUS] = 1;
    return;
  }
}

void ndpi_register_proto_radius (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_RADIUS, "Radius", NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_radius);
}
