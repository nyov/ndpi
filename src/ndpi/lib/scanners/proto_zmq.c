/*
 * proto_zmq.c
 *
 * Copyright (C) 2011-14 - ntop.org
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

static void ndpi_check_zmq(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;
  u_char p0[] =  { 0x00, 0x00, 0x00, 0x05, 0x01, 0x66, 0x6c, 0x6f, 0x77 };
  u_char p1[] =  { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7f };
  u_char p2[] =  { 0x28, 0x66, 0x6c, 0x6f, 0x77, 0x00 };

  if(payload_len == 0) return; /* Shouldn't happen */

  /* Break after 17 packets. */
  if(flow->packet_counter > 17) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "Exclude ZMQ.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_ZMQ] = 1;
    return;
  }

  if(flow->l4.tcp.prev_zmq_pkt_len == 0) {
    flow->l4.tcp.prev_zmq_pkt_len = ndpi_min(packet->payload_packet_len, 10);
    memcpy(flow->l4.tcp.prev_zmq_pkt, packet->payload, flow->l4.tcp.prev_zmq_pkt_len);
    return; /* Too early */
  }

  if(payload_len == 2) {
    if(flow->l4.tcp.prev_zmq_pkt_len == 2) {
      if((memcmp(packet->payload, "\01\01", 2) == 0)
	 && (memcmp(flow->l4.tcp.prev_zmq_pkt, "\01\02", 2) == 0)) {
	flow->ndpi_result_app = NDPI_RESULT_APP_ZMQ;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_ZMQ] = 1;
	return;
      }
    } else if(flow->l4.tcp.prev_zmq_pkt_len == 9) {
      if((memcmp(packet->payload, "\00\00", 2) == 0)
	 && (memcmp(flow->l4.tcp.prev_zmq_pkt, p0, 9) == 0)) {
	flow->ndpi_result_app = NDPI_RESULT_APP_ZMQ;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_ZMQ] = 1;
	return;
      }
    } else if(flow->l4.tcp.prev_zmq_pkt_len == 10) {
      if((memcmp(packet->payload, "\01\02", 2) == 0)
	 && (memcmp(flow->l4.tcp.prev_zmq_pkt, p1, 10) == 0)) {
	flow->ndpi_result_app = NDPI_RESULT_APP_ZMQ;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_ZMQ] = 1;
	return;
      }
    }
  } else if(payload_len >= 10) {
    if(flow->l4.tcp.prev_zmq_pkt_len == 10) {
      if(((memcmp(packet->payload, p1, 10) == 0)
	  && (memcmp(flow->l4.tcp.prev_zmq_pkt, p1, 10) == 0))
	 || ((memcmp(&packet->payload[1], p2, sizeof(p2)) == 0)
	     && (memcmp(&flow->l4.tcp.prev_zmq_pkt[1], p2, sizeof(p2)) == 0))) {
	flow->ndpi_result_app = NDPI_RESULT_APP_ZMQ;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_ZMQ] = 1;
	return;
      }
    }
  }
}

void ndpi_search_zmq(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "ZMQ detection...\n");

  if (packet->tcp_retransmission == 0) {
    ndpi_check_zmq(ndpi_struct, flow);
  }
}

void ndpi_register_proto_zmq (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_ZMQ, "ZeroMQ", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_zmq);
}
