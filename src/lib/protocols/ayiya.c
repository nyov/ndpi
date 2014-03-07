/*
 * ayiya.c
 *
 * Copyright (C) 2011-14 - ntop.org
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

/* http://en.wikipedia.org/wiki/Anything_In_Anything */

#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_AYIYA

static void ndpi_search_setup_ayiya(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t i;
  u_int16_t packet_len;

  /* 1. ayiya is udp based, port 5072 */
  if ((packet->udp->source == htons(5072) || packet->udp->dest == htons(5072))
      /* check for ayiya new packet */
      && (packet->payload_packet_len > 44)) {
    /* FINISH */

    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_AYIYA, NDPI_REAL_PROTOCOL);
  } else
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_AYIYA);
}

void ndpi_search_ayiya(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  //      struct ndpi_flow_struct       *flow=ndpi_struct->flow;
  //      struct ndpi_id_struct         *src=ndpi_struct->src;
  //      struct ndpi_id_struct         *dst=ndpi_struct->dst;

  if(packet->udp
     && (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN))
    ndpi_search_setup_ayiya(ndpi_struct, flow);
}
#endif
