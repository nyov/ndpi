/*
 * proto_icecast.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
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

#include "ndpi_api.h"

void ndpi_search_icecast(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t i;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search icecast.\n");

  if ((packet->payload_packet_len < 500 &&
       packet->payload_packet_len >= 7 && memcmp(packet->payload, "SOURCE ", 7) == 0)
      || flow->l4.tcp.icecast_stage) {
    ndpi_parse_packet_line_info_unix(ndpi_struct, flow);
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Icecast lines=%d\n", packet->parsed_unix_lines);
    for (i = 0; i < packet->parsed_unix_lines; i++) {
      if (packet->unix_line[i].ptr != NULL && packet->unix_line[i].len > 4
	  && memcmp(packet->unix_line[i].ptr, "ice-", 4) == 0) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Icecast detected.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_ICECAST;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_ICECAST] = 1;
	return;
      }
    }

    if (packet->parsed_unix_lines < 1 && !flow->l4.tcp.icecast_stage) {
      flow->l4.tcp.icecast_stage = 1;
      return;
    }
  }
  
  if (flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP] == 1) {
    goto icecast_exclude;
  }

  if (packet->packet_direction == flow->setup_packet_direction && flow->packet_counter < 10) {
    return;
  }

  if (packet->packet_direction != flow->setup_packet_direction) {
    /* server answer, now test Server for Icecast */

    ndpi_parse_packet_line_info(ndpi_struct, flow);

    if (packet->server_line.ptr != NULL && packet->server_line.len > NDPI_STATICSTRING_LEN("Icecast") &&
	memcmp(packet->server_line.ptr, "Icecast", NDPI_STATICSTRING_LEN("Icecast")) == 0) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Icecast detected.\n");
      /* TODO maybe store the previous protocol type as subtype?
       *      e.g. ogg or mpeg
       */
      flow->ndpi_result_app = NDPI_RESULT_APP_ICECAST;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_ICECAST] = 1;
      return;
    }
  }

 icecast_exclude:
  flow->ndpi_excluded_app[NDPI_RESULT_APP_ICECAST] = 1;
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Icecast excluded.\n");
}

void ndpi_register_proto_icecast (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_ICECAST, "IceCast", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_icecast);
}
