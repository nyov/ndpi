/*
 * proto_redis.c
 *
 * Copyright (C) 2011-14 - ntop.org
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

static void ndpi_check_redis(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;  
  u_int32_t payload_len = packet->payload_packet_len;
  
  if(payload_len == 0) return; /* Shouldn't happen */

  /* Break after 20 packets. */
  if(flow->packet_counter > 20) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude Redis.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_REDIS] = 1;
    return;
  }

  if(packet->packet_direction == 0)
    flow->redis_s2d_first_char = packet->payload[0];
  else
    flow->redis_d2s_first_char = packet->payload[0];

  if((flow->redis_s2d_first_char != '\0') && (flow->redis_d2s_first_char != '\0')) {
    /*
     *1
     $4
     PING
     +PONG
     *3
     $3
     SET
     $19
     dns.cache.127.0.0.1
     $9
     localhost
     +OK
    */

    if(((flow->redis_s2d_first_char == '*') 
	&& ((flow->redis_d2s_first_char == '+') || (flow->redis_d2s_first_char == ':')))
       || ((flow->redis_d2s_first_char == '*') 
	   && ((flow->redis_s2d_first_char == '+') || (flow->redis_s2d_first_char == ':')))) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found Redis.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_REDIS;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_REDIS] = 1;
    } else {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude Redis.\n");
      flow->ndpi_excluded_app[NDPI_RESULT_APP_REDIS] = 1;     
    }
  } else
    return; /* Too early */
}

void ndpi_search_redis(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Redis detection...\n");

  if (packet->tcp_retransmission == 0) {
    ndpi_check_redis(ndpi_struct, flow);
  }
}

void ndpi_register_proto_redis (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {6379, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_REDIS, "Redis", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_redis);
}
