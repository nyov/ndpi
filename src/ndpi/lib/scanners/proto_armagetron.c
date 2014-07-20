/*
 * proto_armagetron.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
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

#include "ndpi_protocols.h"

void ndpi_search_armagetron(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search armagetron.\n");


  if (packet->payload_packet_len > 10) {
    /* login request */
    if (get_u_int32_t(packet->payload, 0) == htonl(0x000b0000)) {
      const u_int16_t dataLength = ntohs(get_u_int16_t(packet->payload, 4));
      if (dataLength == 0 || dataLength * 2 + 8 != packet->payload_packet_len)
	goto exclude;
      if (get_u_int16_t(packet->payload, 6) == htons(0x0008)
	  && get_u_int16_t(packet->payload, packet->payload_packet_len - 2) == 0) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "detected armagetron.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_ARMAGETRON;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_ARMAGETRON] = 1;
	return;
      }
    }
    /* sync_msg */
    if (packet->payload_packet_len == 16 && get_u_int16_t(packet->payload, 0) == htons(0x001c)
	&& get_u_int16_t(packet->payload, 2) != 0) {
      const u_int16_t dataLength = ntohs(get_u_int16_t(packet->payload, 4));
      if (dataLength != 4)
	goto exclude;
      if (get_u_int32_t(packet->payload, 6) == htonl(0x00000500) && get_u_int32_t(packet->payload, 6 + 4) == htonl(0x00010000)
	  && get_u_int16_t(packet->payload, packet->payload_packet_len - 2) == 0) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "detected armagetron.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_ARMAGETRON;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_ARMAGETRON] = 1;
	return;
      }
    }

    /* net_sync combination */
    if (packet->payload_packet_len > 50 && get_u_int16_t(packet->payload, 0) == htons(0x0018)
	&& get_u_int16_t(packet->payload, 2) != 0) {
      u_int16_t val;
      const u_int16_t dataLength = ntohs(get_u_int16_t(packet->payload, 4));
      if (dataLength == 0 || dataLength * 2 + 8 > packet->payload_packet_len)
	goto exclude;
      val = get_u_int16_t(packet->payload, 6 + 2);
      if (val == get_u_int16_t(packet->payload, 6 + 6)) {
	val = ntohs(get_u_int16_t(packet->payload, 6 + 8));
	if ((6 + 10 + val + 4) < packet->payload_packet_len
	    && (get_u_int32_t(packet->payload, 6 + 10 + val) == htonl(0x00010000)
		|| get_u_int32_t(packet->payload, 6 + 10 + val) == htonl(0x00000001))
	    && get_u_int16_t(packet->payload, packet->payload_packet_len - 2) == 0) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "detected armagetron.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_ARMAGETRON;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_ARMAGETRON] = 1;
	  return;
	}
      }
    }
  }

 exclude:
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude armagetron.\n");
  flow->ndpi_excluded_app[NDPI_RESULT_APP_ARMAGETRON] = 1;
}

void ndpi_register_proto_armagetron (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_ARMAGETRON, "Armagetron", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_armagetron);
}
