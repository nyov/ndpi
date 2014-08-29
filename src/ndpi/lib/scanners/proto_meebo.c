/*
 * proto_meebo.c
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

void ndpi_search_meebo(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search meebo.\n");

  /* catch audio/video flows which are flash (rtmp) */
  if (packet->tcp->source == htons(1935) || packet->tcp->dest == htons(1935)) {

    /* TODO: once we have an amf decoder we can more directly access the rtmp fields
     *       if so, we may also exclude earlier */
    if (packet->payload_packet_len > 900) {
      if (memcmp(packet->payload + 116, "tokbox/", NDPI_STATICSTRING_LEN("tokbox/")) == 0 ||
	  memcmp(packet->payload + 316, "tokbox/", NDPI_STATICSTRING_LEN("tokbox/")) == 0) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found meebo/tokbox flash flow.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_MEEBO;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_MEEBO] = 1;
	return;
      }
    }

    if (flow->packet_counter < 16 && flow->packet_direction_counter[flow->setup_packet_direction] < 6) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "need next packet.\n");
      return;
    }

    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude meebo.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_MEEBO] = 1;
    return;
  }

  if (((flow->ndpi_result_base == NDPI_RESULT_BASE_HTTP) ||
       ((packet->payload_packet_len > 3 && memcmp(packet->payload, "GET ", 4) == 0)
	|| (packet->payload_packet_len > 4 && memcmp(packet->payload, "POST ", 5) == 0))) && flow->packet_counter == 1) {
    
    u_int8_t host_or_referer_match = 0;
    ndpi_parse_packet_line_info(ndpi_struct, flow);
  
    if (packet->host_line.ptr != NULL
	&& packet->host_line.len >= 9
	&& memcmp(&packet->host_line.ptr[packet->host_line.len - 9], "meebo.com", 9) == 0) {

      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found Meebo host\n");
      host_or_referer_match = 1;
    } else if (packet->host_line.ptr != NULL
	       && packet->host_line.len >= 10
	       && memcmp(&packet->host_line.ptr[packet->host_line.len - 10], "tokbox.com", 10) == 0) {

      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found tokbox host\n");
      /* set it to 2 to avoid having plain tokbox traffic detected as meebo */
      host_or_referer_match = 2;
    } else if (packet->host_line.ptr != NULL && packet->host_line.len >= NDPI_STATICSTRING_LEN("74.114.28.110")
	       && memcmp(&packet->host_line.ptr[packet->host_line.len - NDPI_STATICSTRING_LEN("74.114.28.110")],
			 "74.114.28.110", NDPI_STATICSTRING_LEN("74.114.28.110")) == 0) {

      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found meebo IP\n");
      host_or_referer_match = 1;
    } else if (packet->referer_line.ptr != NULL &&
	       packet->referer_line.len >= NDPI_STATICSTRING_LEN("http://www.meebo.com/") &&
	       memcmp(packet->referer_line.ptr, "http://www.meebo.com/",
		      NDPI_STATICSTRING_LEN("http://www.meebo.com/")) == 0) {

      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found meebo referer\n");
      host_or_referer_match = 1;
    } else if (packet->referer_line.ptr != NULL &&
	       packet->referer_line.len >= NDPI_STATICSTRING_LEN("http://mee.tokbox.com/") &&
	       memcmp(packet->referer_line.ptr, "http://mee.tokbox.com/",
		      NDPI_STATICSTRING_LEN("http://mee.tokbox.com/")) == 0) {

      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found tokbox referer\n");
      host_or_referer_match = 1;
    } else if (packet->referer_line.ptr != NULL &&
	       packet->referer_line.len >= NDPI_STATICSTRING_LEN("http://74.114.28.110/") &&
	       memcmp(packet->referer_line.ptr, "http://74.114.28.110/",
		      NDPI_STATICSTRING_LEN("http://74.114.28.110/")) == 0) {

      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found meebo IP referer\n");
      host_or_referer_match = 1;
    }

    if (host_or_referer_match) {
      if (host_or_referer_match == 1) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found Meebo traffic based on host/referer\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_MEEBO;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_MEEBO] = 1;
	return;
      }
    }
  }

  if (flow->packet_counter < 5 && (flow->ndpi_excluded_base[NDPI_RESULT_BASE_SSL] == 0)) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "ssl not yet excluded. need next packet.\n");
    return;
  }

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude meebo.\n");
  flow->ndpi_excluded_app[NDPI_RESULT_APP_MEEBO] = 1;
}

void ndpi_register_proto_meebo (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_MEEBO, "Meebo", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_meebo);
}
