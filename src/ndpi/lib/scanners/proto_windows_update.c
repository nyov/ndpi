/*
 * proto_windows_update.c
 *
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

void ndpi_search_windows_update(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  
  /* Break after 20 packets. */
  if (flow->packet_counter > 20) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude Windows Update.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_WINDOWS_UPDATE] = 1;
    return;
  }

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search for Windows Update.\n");
  
  if (packet->user_agent_line.len >= 20 && memcmp(packet->user_agent_line.ptr, "Windows-Update-Agent", 20) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Windows Update detected\n");
    flow->ndpi_result_app = NDPI_RESULT_APP_WINDOWS_UPDATE;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_WINDOWS_UPDATE] = 1;
  }
}

void ndpi_register_proto_windows_update (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_base (ndpi_mod, NDPI_RESULT_APP_WINDOWS_UPDATE, "WindowsUpdate", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_windows_update);
}
