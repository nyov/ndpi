/*
 * proto_vmware.c
 *
 * Copyright (C) 2011-13 - ntop.org
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

void ndpi_search_vmware(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
    
  /* Check whether this is an VMWARE flow */
  if((packet->payload_packet_len == 66)
     && (ntohs(packet->udp->dest) == 902)
     && ((packet->payload[0] & 0xFF) == 0xA4)) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found vmware.\n");
    flow->ndpi_result_app = NDPI_RESULT_APP_VMWARE;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_VMWARE] = 1;
  } else {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude vmware.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_VMWARE] = 1;
  }
}

void ndpi_register_proto_vmware (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {903, 0, 0, 0, 0};
  int udp_ports[5] = {902, 903, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_VMWARE, "VMware", NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_vmware);
}
