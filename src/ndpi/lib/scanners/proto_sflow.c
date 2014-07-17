/*
 * proto_sflow.c
 *
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

#include "ndpi_utils.h"

void ndpi_search_sflow(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "sflow detection...\n");
  
    /* Break after 20 packets. */
  if (flow->packet_counter > 20) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude sflow.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_SFLOW] = 1;
    return;
  }
  
  struct ndpi_packet_struct *packet = &flow->packet;  
  u_int32_t payload_len = packet->payload_packet_len;

  if ((packet->udp != NULL)
     && (payload_len >= 24)
     /* Version */
     && (packet->payload[0] == 0) && (packet->payload[1] == 0) && (packet->payload[2] == 0)
     && ((packet->payload[3] == 2) || (packet->payload[3] == 5))) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found sflow.\n");
    flow->ndpi_result_app = NDPI_RESULT_APP_SFLOW;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_SFLOW] = 1;
    return;
  }
}

void ndpi_register_proto_sflow (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {6343, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_SFLOW, "sFlow", NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_sflow);
}
