/*
 * proto_warcraft3.c
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

void ndpi_search_warcraft3(struct ndpi_detection_module_struct
			   *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  u_int32_t l; /* 
		  Leave it as u_int32_t because otherwise 'u_int16_t temp' 
		  might overflood it and thus generate an infinite loop
	       */

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search WARCRAFT3\n");


  if (flow->packet_counter == 1 && packet->payload_packet_len == 1 && packet->payload[0] == 0x01) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe warcraft3: packet_len == 1\n");
    return;
  } else if (packet->payload_packet_len >= 4 && (packet->payload[0] == 0xf7 || packet->payload[0] == 0xff)) {

    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "packet_payload begins with 0xf7 or 0xff\n");

    l = packet->payload[2] + (packet->payload[3] << 8);	// similar to ntohs

    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "l = %u \n", l);

    while (l <= (packet->payload_packet_len - 4)) {
      if (packet->payload[l] == 0xf7) {
	u_int16_t temp = (packet->payload[l + 2 + 1] << 8) + packet->payload[l + 2];
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "another f7 visited.\n");

	if((temp <= 2) || (temp > 1500)) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "break\n");
	  break;
	} else {
	  l += temp;
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "l = %u \n", l);
	}
      } else {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "break\n");
	break;
      }
    }

    if (l == packet->payload_packet_len) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe WARCRAFT3\n");
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "flow->packet_counter = %u \n",
	       flow->packet_counter);
      if (flow->packet_counter > 2) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "detected WARCRAFT3\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_WARCRAFT3;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_WARCRAFT3] = 1;
	return;
      }
      return;
    }
  }

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "no warcraft3 detected.\n");
  flow->ndpi_excluded_app[NDPI_RESULT_APP_WARCRAFT3] = 1;
}

void ndpi_register_proto_warcraft3 (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_WARCRAFT3, "Warcraft3", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_warcraft3);
}
