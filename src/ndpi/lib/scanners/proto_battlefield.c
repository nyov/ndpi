/*
 * proto_battlefield.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
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

void ndpi_search_battlefield(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  if (flow->l4.udp.battlefield_stage == 0) {
    if (packet->payload_packet_len == 46 && packet->payload[2] == 0 && packet->payload[4] == 0
	&& get_u_int32_t(packet->payload, 7) == htonl(0x98001100)) {
      flow->l4.udp.battlefield_stage = 3 + packet->packet_direction;
      return;
    }
  } else if (flow->l4.udp.battlefield_stage == 4 - packet->packet_direction) {
    if (packet->payload_packet_len == 7
	&& (packet->payload[0] == 0x02 || packet->payload[packet->payload_packet_len - 1] == 0xe0)) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
	       "Battlefield message and reply detected.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_BATTLEFIELD;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_BATTLEFIELD] = 1;
      return;
    }
  }

  if (packet->payload_packet_len == 18 && memcmp(&packet->payload[5], "battlefield2\x00", 13) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Battlefield 2 hello packet detected.\n");
    flow->ndpi_result_app = NDPI_RESULT_APP_BATTLEFIELD;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_BATTLEFIELD] = 1;
    return;
  } else if (packet->payload_packet_len > 10 &&
	     (memcmp(packet->payload, "\x11\x20\x00\x01\x00\x00\x50\xb9\x10\x11", 10) == 0
	      || memcmp(packet->payload, "\x11\x20\x00\x01\x00\x00\x30\xb9\x10\x11", 10) == 0
	      || memcmp(packet->payload, "\x11\x20\x00\x01\x00\x00\xa0\x98\x00\x11", 10) == 0)) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Battlefield safe pattern detected.\n");
    flow->ndpi_result_app = NDPI_RESULT_APP_BATTLEFIELD;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_BATTLEFIELD] = 1;
    return;
  }

  flow->ndpi_excluded_app[NDPI_RESULT_APP_BATTLEFIELD] = 1;
  return;
}

void ndpi_register_proto_battlefield (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_BATTLEFIELD, "BattleField", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_battlefield);
}
