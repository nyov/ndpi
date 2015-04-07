/*
 * proto_rtsp.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
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

/* this function searches for a rtsp-"handshake" over tcp or udp. */
void ndpi_search_rtsp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  
  /* Break after 20 packets. */
  if (flow->packet_counter > 20) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude RTSP.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_RTSP] = 1;
    return;
  }
  
  struct ndpi_packet_struct *packet = &flow->packet;
	
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;
  
  if (packet->accept_line.ptr != NULL && packet->accept_line.len >= 28 && memcmp(packet->accept_line.ptr, "application/x-rtsp-tunnelled", 28) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "RTSP detected\n");
    flow->ndpi_result_app = NDPI_RESULT_APP_RTSP;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_RTSP] = 1;
  }

  if (flow->rtsprdt_stage == 0) {
    flow->rtsprdt_stage = 1 + packet->packet_direction;
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe handshake 1; need next packet, return.\n");
    return;
  }

  if (flow->packet_counter < 3 && flow->rtsprdt_stage == 1 + packet->packet_direction) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe handshake 2; need next packet.\n");
    return;
  }

  if (packet->payload_packet_len > 20 && flow->rtsprdt_stage == 2 - packet->packet_direction) {
    char buf[32] = { 0 };
    u_int len = packet->payload_packet_len;

    if (len >= (sizeof(buf)-1)) {
      len = sizeof(buf)-1;
    }
    
    strncpy(buf, (const char*)packet->payload, len);
    
    // RTSP Server Message
    if ((memcmp(packet->payload, "RTSP/1.0 ", 9) == 0) || (strstr(buf, "rtsp://") != NULL)) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found RTSP/1.0 .\n");

      if (dst != NULL) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found dst.\n");
	ndpi_packet_src_ip_get(packet, &dst->rtsp_ip_address);
	dst->rtsp_timer = packet->tick_timestamp;
	dst->rtsp_ts_set = 1;
      }
      
      if (src != NULL) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found src.\n");
	ndpi_packet_dst_ip_get(packet, &src->rtsp_ip_address);
	src->rtsp_timer = packet->tick_timestamp;
	src->rtsp_ts_set = 1;
      }
      
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found RTSP.\n");
      flow->rtsp_control_flow = 1;
      flow->ndpi_result_app = NDPI_RESULT_APP_RTSP;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_RTSP] = 1;
      return;
    }
  }
}

void ndpi_register_proto_rtsp (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {554, 0, 0, 0, 0};
  int udp_ports[5] = {554, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_RTSP, "RTSP", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_rtsp);
}
