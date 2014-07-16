/*
 * proto_megaco.c
 *
 * Copyright (C) 2014 Tomasz Bujlow <tomasz@skatnet.dk>
 * Copyright (C) 2014 by Gianluca Costa http://www.capanalysis.net
 * Copyright (C) 2012-14 - ntop.org
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
#include "ndpi_protocols.h"

void ndpi_search_megaco(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search for MEGACO.\n");
  
  if(packet->udp != NULL) {
    if((packet->payload_packet_len > 4 && packet->payload[0] == '!' && packet->payload[1] == '/' &&
        packet->payload[2] == '1' && packet->payload[3] == ' ' && packet->payload[4] == '[')
       || (packet->payload_packet_len > 9 && packet->payload[0] == 'M' && packet->payload[1] == 'E' &&
        packet->payload[2] == 'G' && packet->payload[3] == 'A' && packet->payload[4] == 'C' &&
        packet->payload[5] == 'O' && packet->payload[6] == '/' &&
        packet->payload[7] == '1' && packet->payload[8] == ' ' && packet->payload[9] == '[')) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found MEGACO.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_MEGACO;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_MEGACO] = 1;
      return;
    } 
  }

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude MEGACO.\n");
  flow->ndpi_excluded_app[NDPI_RESULT_APP_MEGACO] = 1;
}

void ndpi_register_proto_megaco (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {2944, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_MEGACO, "Megaco", NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_megaco);
}
