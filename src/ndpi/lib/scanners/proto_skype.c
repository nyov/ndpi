/*
 * proto_skype.c
 *
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

void ndpi_search_skype(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;
  
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "skype detection...\n");
  
  /*
    Skype AS8220
    212.161.8.0/24
  */
  if(((ntohl(packet->iph->saddr) & 0xFFFFFF00 /* 255.255.255.0 */) == 0xD4A10800 /* 212.161.8.0 */)
     || ((ntohl(packet->iph->daddr) & 0xFFFFFF00 /* 255.255.255.0 */) == 0xD4A10800 /* 212.161.8.0 */)
     /* || is_skype_connection(ndpi_struct, packet->iph->saddr, packet->iph->daddr) */
     ) {
    flow->ndpi_result_app = NDPI_RESULT_APP_SKYPE;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_SKYPE] = 1;
    return;
  }

  if(packet->udp != NULL) {
    flow->l4.udp.skype_packet_id++;

    if(flow->l4.udp.skype_packet_id < 5) {
      /* skype-to-skype */
      if(((payload_len == 3) && ((packet->payload[2] & 0x0F)== 0x0d))
	 || ((payload_len >= 16)
	     && (packet->payload[0] != 0x30) /* Avoid invalid SNMP detection */
	     && (packet->payload[2] == 0x02))) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found skype.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_SKYPE;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_SKYPE] = 1;
      }

      return;
    }

    flow->ndpi_excluded_app[NDPI_RESULT_APP_SKYPE] = 1;
    return;
  } else if(packet->tcp != NULL) {
    flow->l4.tcp.skype_packet_id++;

    if(flow->l4.tcp.skype_packet_id < 3) {
      ; /* Too early */
    } else if((flow->l4.tcp.skype_packet_id == 3)
	      /* We have seen the 3-way handshake */
	      && flow->l4.tcp.seen_syn
	      && flow->l4.tcp.seen_syn_ack
	      && flow->l4.tcp.seen_ack) {
      if((payload_len == 8) || (payload_len == 3)) {

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found skype.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_SKYPE;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_SKYPE] = 1;
      }

    } else
      flow->ndpi_excluded_app[NDPI_RESULT_APP_SKYPE] = 1;

    return;
  }
}

void ndpi_register_proto_skype (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_SKYPE, "Skype", NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_skype);
}
