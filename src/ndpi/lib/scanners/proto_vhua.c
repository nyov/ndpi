/*
 * proto_vhua.c
 *
 * Copyright (C) 2011-14 - ntop.org
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

/*
  http://www.vhua.com 
  Skype-like Chinese phone protocol
 */

void ndpi_search_vhua(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "VHUA detection...\n");
  
  u_int32_t payload_len = packet->payload_packet_len;
  u_char p0[] =  {0x05, 0x14, 0x3a, 0x05, 0x08, 0xf8, 0xa1, 0xb1, 0x03};

  if (payload_len == 0) {
    return; /* Shouldn't happen */
  }

  /* Break after 3 packets. */
  if ((flow->packet_counter > 3) || (packet->udp == NULL) || (packet->payload_packet_len < sizeof(p0))) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "Exclude VHUA.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_VHUA] = 1;
  } else if (memcmp(packet->payload, p0, sizeof(p0)) == 0) {
    flow->ndpi_result_app = NDPI_RESULT_APP_VHUA;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_VHUA] = 1;
  }
}

void ndpi_register_proto_vhua (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {58267, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_VHUA, "Vhua", NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_vhua);
}
