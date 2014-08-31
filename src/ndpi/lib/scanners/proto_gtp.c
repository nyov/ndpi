/*
 * proto_gtp.c
 *
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

struct gtp_header_generic {
  u_int8_t flags, message_type;
  u_int16_t message_len;
  u_int32_t teid;
};

void ndpi_search_gtp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "gtp detection...\n");

  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  if ((packet->udp != NULL) && (payload_len > sizeof(struct gtp_header_generic))) {
    u_int32_t gtp_u = ntohs(2152);
    u_int32_t gtp_c = ntohs(2123);
    u_int32_t gtp_v0 = ntohs(3386);

    if ((packet->udp->source == gtp_u) || (packet->udp->dest == gtp_u)
       || (packet->udp->source == gtp_c) || (packet->udp->dest == gtp_c)
       || (packet->udp->source == gtp_v0) || (packet->udp->dest == gtp_v0)
       ) {
      struct gtp_header_generic *gtp = (struct gtp_header_generic*)packet->payload;
      u_int8_t gtp_version = (gtp->flags & 0xE0) >> 5;

      if ((gtp_version == 0) || (gtp_version == 1) || (gtp_version == 2)) {
	u_int16_t message_len = ntohs(gtp->message_len);
	
	if (message_len <= (payload_len-sizeof(struct gtp_header_generic))) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found gtp.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_GTP;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_GTP] = 1;
	  return;
	}
      }
    }
  }

  flow->ndpi_excluded_app[NDPI_RESULT_APP_GTP] = 1;
  return;
}

void ndpi_register_proto_gtp (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {2152, 2123, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_GTP, "GTP", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_gtp);
}
