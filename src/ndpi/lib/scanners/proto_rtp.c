/*
 * proto_rtp.c
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

void ndpi_search_rtp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  
  /* Break after 20 packets. */
  if (flow->packet_counter > 20) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude RTP.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_RTP] = 1;
    return;
  }

  if ((packet->udp == NULL) || (ntohs(packet->udp->source) <= 1023) || (ntohs(packet->udp->dest) <= 1023))
    return;
  
  u_int8_t * payload = packet->payload;
  u_int16_t payload_len = packet->payload_packet_len;
  u_int8_t payload_type = payload[1] & 0x7F;
  u_int32_t *ssid = (u_int32_t*)&payload[8];

  /* Check whether this is an RTP flow */
  if ((payload_len >= 12)
     && ((payload[0] & 0xFF) == 0x80) /* RTP magic byte[1] */
     && ((payload_type < 128          /* http://anonsvn.wireshark.org/wireshark/trunk/epan/dissectors/packet-rtp.c */))
     && (*ssid != 0)
     ) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found rtp.\n");
    flow->ndpi_result_app = NDPI_RESULT_APP_RTP;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_RTP] = 1;	
  } else {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude rtp.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_RTP] = 1;
  }
}

void ndpi_register_proto_rtp (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_RTP, "RTP", NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_rtp);
}
