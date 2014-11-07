/*
 * proto_lotus_notes.c
 *
 * Copyright (C) 2012-13 - ntop.org
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

void ndpi_search_lotus_notes(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "lotus_notes detection...\n");
  
  struct ndpi_packet_struct *packet = &flow->packet;  
  u_int32_t payload_len = packet->payload_packet_len;

  if(packet->tcp != NULL) {
    flow->l4.tcp.lotus_notes_packet_id++;

    if((flow->l4.tcp.lotus_notes_packet_id == 1)
       /* We have seen the 3-way handshake */
       && flow->l4.tcp.seen_syn
       && flow->l4.tcp.seen_syn_ack
       && flow->l4.tcp.seen_ack) {
      
      if(payload_len > 16) {
	char lotus_notes_header[] = { 0x00, 0x00, 0x02, 0x00, 0x00, 0x40, 0x02, 0x0F };
	
	if(memcmp(&packet->payload[6], lotus_notes_header, sizeof(lotus_notes_header)) == 0) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found lotus_notes.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_LOTUS_NOTES;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_LOTUS_NOTES] = 1;
	}

	return;
      }

      flow->ndpi_excluded_app[NDPI_RESULT_APP_LOTUS_NOTES] = 1;
      
    } else if(flow->l4.tcp.lotus_notes_packet_id > 3) {
      flow->ndpi_excluded_app[NDPI_RESULT_APP_LOTUS_NOTES] = 1;
    }
    
    return;
  }
}

void ndpi_register_proto_lotus_notes (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {1352, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_LOTUS_NOTES, "LotusNotes", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_lotus_notes);
}
