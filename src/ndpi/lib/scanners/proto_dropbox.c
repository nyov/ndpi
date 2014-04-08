/*
 * proto_dropbox.c
 *
 * Copyright (C) 2011-13 by ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */


#include "ndpi_utils.h"

void ndpi_search_dropbox(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "dropbox detection...\n");
  
  if (packet->iph != NULL) {
    u_int32_t saddr = ntohl(packet->iph->saddr);
    u_int32_t daddr = ntohl(packet->iph->daddr);
    
    /*
      Dropbox
      108.160.160.0/20
      199.47.216.0/22
    */
    if(((saddr & 0xFFFFF000 /* 255.255.240.0 */) == 0x6CA0A000 /* 108.160.160.0 */) || ((daddr & 0xFFFFF000 /* 255.255.240.0 */) == 0x6CA0A000 /* 108.160.160.0 */)
       || ((saddr & 0xFFFFFC00 /* 255.255.240.0 */) == 0xC72FD800 /* 199.47.216.0 */) || ((daddr & 0xFFFFFC00 /* 255.255.240.0 */) == 0xC72FD800 /* 199.47.216.0 */)
       ) {
      flow->ndpi_result_app = NDPI_RESULT_APP_DROPBOX;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_DROPBOX] = 1;
      return;
    }

    if(((saddr & 0xFFFFF000 /* 255.255.240.0.0 */) == 0x6CA0A000 /* 108.160.160.0 */)
       || ((daddr & 0xFFFFF000 /* 255.255.240.0 */) == 0x6CA0A000 /* 108.160.160.0 */)) {
      flow->ndpi_result_app = NDPI_RESULT_APP_DROPBOX;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_DROPBOX] = 1;
      return;
    }    
  }  
  
  if (packet->udp != NULL) {
    u_int16_t dropbox_port = htons(17500);

    if ((packet->udp->source == dropbox_port) && (packet->udp->dest == dropbox_port)) {
      if(payload_len > 2) {
	if(strncmp((const char *)packet->payload, "{\"", 2) == 0) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found dropbox.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_DROPBOX;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_DROPBOX] = 1;
	  return;
	}
      }
    }
  }
  
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude dropbox.\n");
  flow->ndpi_excluded_app[NDPI_RESULT_APP_DROPBOX] = 1;
}

void ndpi_register_proto_dropbox (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_DROPBOX, "Dropbox", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_dropbox);
}
