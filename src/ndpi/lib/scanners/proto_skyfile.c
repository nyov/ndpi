/*
 * proto_skyfile.c
 *
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

void ndpi_search_skyfile(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search for Skyfile.\n");
  
   if (packet->iph != NULL) {
     
    u_int32_t saddr = ntohl(packet->iph->saddr);
    u_int32_t daddr = ntohl(packet->iph->daddr);

    if (packet->tcp != NULL) {
      sport = ntohs(packet->tcp->source), dport = ntohs(packet->tcp->dest);
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Looking for Skyfile over TCP.\n");
    } else {
      sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Looking for Skyfile over UDP.\n");
    }
    
    /* Skyfile (host 193.252.234.246 or host 10.10.102.80) */
    if ((saddr == 0xC1FCEAF6) || (daddr == 0xC1FCEAF6) || (saddr == 0x0A0A6650) || (daddr == 0x0A0A6650)) {
      if ((sport == 4708) || (dport == 4708)) {
	flow->ndpi_result_app = NDPI_RESULT_APP_SKYFILE_PREPAID;
      } else if ((sport == 4709) || (dport == 4709)) {
	flow->ndpi_result_app = NDPI_RESULT_APP_SKYFILE_RUDICS;
      } else if ((sport == 4710) || (dport == 4710)) {
	flow->ndpi_result_app = NDPI_RESULT_APP_SKYFILE_POSTPAID;
      }
    }
   }
  
  flow->ndpi_excluded_app[NDPI_RESULT_APP_SKYFILE_PREPAID] = 1;
  flow->ndpi_excluded_app[NDPI_RESULT_APP_SKYFILE_RUDICS] = 1;
  flow->ndpi_excluded_app[NDPI_RESULT_APP_SKYFILE_POSTPAID] = 1;
  
}

void ndpi_register_proto_skyfile (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {4708, 4709, 4710, 0, 0};
  int udp_ports[5] = {4708, 4709, 4710, 0, 0};

  ndpi_initialize_scanner_base (ndpi_mod, NDPI_RESULT_APP_SKYFILE_PREPAID, "SkyFile_PrePaid", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_skyfile);
  ndpi_initialize_scanner_base (ndpi_mod, NDPI_RESULT_APP_SKYFILE_RUDICS, "SkyFile_Rudics", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, NULL);
  ndpi_initialize_scanner_base (ndpi_mod, NDPI_RESULT_APP_SKYFILE_POSTPAID, "SkyFile_PostPaid", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, NULL);
}
