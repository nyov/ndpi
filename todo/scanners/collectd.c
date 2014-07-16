/*
 * collectd.c
 *
 * Copyright (C) 2014 - ntop.org
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

#include "ndpi_protocols.h"

#ifdef NDPI_OLD_RESULT_APP_COLLECTD

void ndpi_search_collectd(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int len = 0;

  NDPI_LOG(NDPI_OLD_RESULT_APP_COLLECTD, ndpi_struct, NDPI_LOG_DEBUG, "search collectd.\n");
  
  if (packet->udp == NULL) return;


  while(len < packet->payload_packet_len) {
    u_int16_t elem_len = ntohs(*((u_int16_t*)&packet->payload[len+2]));

    if (elem_len == 0) break;

    len += elem_len;
  }

  if(len == packet->payload_packet_len) {
    NDPI_LOG(NDPI_OLD_RESULT_APP_COLLECTD, ndpi_struct, NDPI_LOG_DEBUG, "found COLLECTD.\n");      
    ndpi_int_add_connection(ndpi_struct, flow, NDPI_OLD_RESULT_APP_COLLECTD, NDPI_REAL_PROTOCOL);
  } else {
    NDPI_LOG(NDPI_OLD_RESULT_APP_COLLECTD, ndpi_struct, NDPI_LOG_DEBUG, "exclude COLLECTD.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_OLD_RESULT_APP_COLLECTD);
  }
}
#endif
