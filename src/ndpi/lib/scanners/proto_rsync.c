/*
 * proto_rsync.c
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
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

void ndpi_search_rsync(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search for RSYNC.\n");

  if (packet->tcp != NULL) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "calculating RSYNC over tcp.\n");
    
    /*
     * Should match: memcmp(packet->payload, "@RSYN NCD: 28", 14) == 0)
     */
    if (packet->payload_packet_len == 12 && packet->payload[0] == 0x40 &&
	packet->payload[1] == 0x52 && packet->payload[2] == 0x53 &&
	packet->payload[3] == 0x59 && packet->payload[4] == 0x4e &&
	packet->payload[5] == 0x43 && packet->payload[6] == 0x44 &&
	packet->payload[7] == 0x3a ) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found rsync.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_RSYNC;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_RSYNC] = 1;
    }
  } else {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude RSYNC.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_RSYNC] = 1;
  }
}

void ndpi_register_proto_rsync (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {873, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_RSYNC, "RSYNC", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_rsync);
}
