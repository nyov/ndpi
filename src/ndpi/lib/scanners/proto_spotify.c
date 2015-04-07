/*
 * proto_spotify.c
 *
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

void ndpi_search_spotify(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "spotify detection...\n");
  
  if (packet->udp != NULL) {
    u_int16_t spotify_port = htons(57621);

    if((packet->udp->source == spotify_port)
       && (packet->udp->dest == spotify_port)) {
      if(payload_len > 2) {
	if(memcmp(packet->payload, "SpotUdp", 7) == 0) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found spotify udp dissector.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_SPOTIFY;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_SPOTIFY] = 1;
	  return;
	}
      }
    }
  } else if (packet->tcp != NULL) {
    
    if (packet->payload[0] == 0x00 && packet->payload[1] == 0x04 &&
      packet->payload[2] == 0x00 && packet->payload[3] == 0x00&&
      packet->payload[6] == 0x52 && packet->payload[7] == 0x0e &&
      packet->payload[8] == 0x50 ) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found spotify tcp dissector.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_SPOTIFY;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_SPOTIFY] = 1;
      return;
    }
    
    if(packet->iph /* IPv4 Only: we need to support packet->iphv6 at some point */) {
       {
	/*
	Spotify

	78.31.8.0 - 78.31.15.255 (78.31.8.0/22)
	AS29017

	193.235.232.0 - 193.235.235.255 (193.235.232.0/22)
	AS29017
	
	194.132.196.0 - 194.132.199.255 (194.132.198.147/22)
	AS43650

	194.132.176.0 - 194.132.179.255  (194.132.176.0/22)
	AS43650

	194.132.162.0 - 194.132.163.255   (194.132.162.0/24)
	AS43650
      */

	if(((ntohl(packet->iph->saddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0x4E1F0800 /* 78.31.8.0 */)
	   || ((ntohl(packet->iph->daddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0x4E1F0800 /* 78.31.8.0 */)
	   /* **** */
	   || ((ntohl(packet->iph->saddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0xC1EBE800 /* 193.235.232.0 */)
	   || ((ntohl(packet->iph->daddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0xC1EBE800 /* 193.235.232.0 */)
	  /* **** */
	  || ((ntohl(packet->iph->saddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0xC284C400 /* 194.132.196.0 */)
	  || ((ntohl(packet->iph->daddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0xC284C400 /* 194.132.196.0 */)
	  /* **** */
	  || ((ntohl(packet->iph->saddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0xC284A200 /* 194.132.162.0 */)
	  || ((ntohl(packet->iph->daddr) & 0xFFFFFC00 /* 255.255.252.0 */) == 0xC284A200 /* 194.132.162.0 */)
	   ) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found spotify via ip range.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_SPOTIFY;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_SPOTIFY] = 1;
	  return;
	}
      }
    }
  }
  
  /* Break after 20 packets. */
  if (flow->packet_counter > 10) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude Spotify.\n");
    flow->ndpi_excluded_base[NDPI_RESULT_APP_SPOTIFY] = 1;
    return;
  }
}

void ndpi_register_proto_spotify (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_SPOTIFY, "Spotify", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_spotify);
}
