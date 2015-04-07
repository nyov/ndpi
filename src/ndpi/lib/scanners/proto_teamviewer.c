/*
 * proto_teamviewer.c
 *
 * Copyright (C) 2012 by Gianluca Costa xplico.org
 * Copyright (C) 2012-13 - ntop.org
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

void ndpi_search_teamview(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
    
    /* Break after 20 packets. */
    if (flow->packet_counter > 20) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude TeamViewer.\n");
      flow->ndpi_excluded_app[NDPI_RESULT_APP_TEAMVIEWER] = 1;
      return;
    }
    
    if ((flow->ndpi_result_base == NDPI_RESULT_BASE_HTTP) || (flow->ndpi_result_base == NDPI_RESULT_BASE_HTTP_PROXY) || (flow->ndpi_result_base == NDPI_RESULT_BASE_HTTP_CONNECT)) {
      const u_int8_t *pos;
      
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "called teamviewer_check_http_payload: %u %u %u\n", 
        packet->empty_line_position_set, flow->l4.tcp.http_empty_line_seen, packet->empty_line_position);

      if (packet->empty_line_position_set != 0 && (packet->empty_line_position + 5) <= (packet->payload_packet_len)) {

	pos = &packet->payload[packet->empty_line_position] + 2;

	if (pos[0] == 0x17 && pos[1] == 0x24) {
	    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "TeamViewer content in http detected\n");
	    flow->ndpi_result_app = NDPI_RESULT_APP_TEAMVIEWER;
	    flow->ndpi_excluded_app[NDPI_RESULT_APP_TEAMVIEWER] = 1;
	    return;
	}
      }
    }
    
    /*
      TeamViewer
      178.77.120.0/25

      http://myip.ms/view/ip_owners/144885/Teamviewer_Gmbh.html
    */
    if (flow->packet.iph) {
      u_int32_t src = ntohl(flow->packet.iph->saddr);
      u_int32_t dst = ntohl(flow->packet.iph->daddr);

      /* 95.211.37.195 - 95.211.37.203 */
      if (((src >= 1607673283) && (src <= 1607673291))
	|| ((dst >= 1607673283) && (dst <= 1607673291))
	|| ((src & 0xFFFFFF80 /* 255.255.255.128 */) == 0xB24D7800 /* 178.77.120.0 */)
	|| ((dst & 0xFFFFFF80 /* 255.255.255.128 */) == 0xB24D7800 /* 178.77.120.0 */)
	) {
	flow->ndpi_result_app = NDPI_RESULT_APP_TEAMVIEWER;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_TEAMVIEWER] = 1;
	return;
      }
    }

    if (packet->payload_packet_len == 0) {
      return;
    }

    if (packet->udp != NULL) {
      if (packet->payload_packet_len > 13) {
	if (packet->payload[0] == 0x00 && packet->payload[11] == 0x17 && packet->payload[12] == 0x24) { /* byte 0 is a counter/seq number, and at the start is 0 */
	  flow->l4.udp.teamviewer_stage++;
	  if (flow->l4.udp.teamviewer_stage == 4 ||
	      packet->udp->dest == ntohs(5938) || packet->udp->source == ntohs(5938)) {
	    flow->ndpi_result_app = NDPI_RESULT_APP_TEAMVIEWER;
	    flow->ndpi_excluded_app[NDPI_RESULT_APP_TEAMVIEWER] = 1;
	  }
	  return;
	}
      }
    } else if (packet->tcp != NULL) {
      if (packet->payload_packet_len > 2) {
	if (packet->payload[0] == 0x17 && packet->payload[1] == 0x24) {
	  flow->l4.udp.teamviewer_stage++;
	  if (flow->l4.udp.teamviewer_stage == 4 ||
	      packet->tcp->dest == ntohs(5938) || packet->tcp->source == ntohs(5938)) {
	    flow->ndpi_result_app = NDPI_RESULT_APP_TEAMVIEWER;
	    flow->ndpi_excluded_app[NDPI_RESULT_APP_TEAMVIEWER] = 1;
	  }
	  return;
	} else if (flow->l4.udp.teamviewer_stage) {
	  if (packet->payload[0] == 0x11 && packet->payload[1] == 0x30) {
	    flow->l4.udp.teamviewer_stage++;
	    if (flow->l4.udp.teamviewer_stage == 4)
	      flow->ndpi_result_app = NDPI_RESULT_APP_TEAMVIEWER;
	      flow->ndpi_excluded_app[NDPI_RESULT_APP_TEAMVIEWER] = 1;
	  }
	  return;
	}
      }
    }
}

void ndpi_register_proto_teamviewer (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_TEAMVIEWER, "TeamViewer", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP, tcp_ports, udp_ports, ndpi_search_teamview);
}
