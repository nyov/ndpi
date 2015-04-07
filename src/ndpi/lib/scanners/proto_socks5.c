/*
 * proto_socks5.c
 *
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

static void ndpi_check_socks5(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  /* Break after 20 packets. */
  if (flow->packet_counter > 20) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude SOCKS5.\n");
    flow->ndpi_excluded_base[NDPI_RESULT_BASE_SOCKS5] = 1;
    return;
  }

  /* Check if we so far detected the protocol in the request or not. */
  if (flow->socks5_stage == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "SOCKS5 stage 0: \n");

    if ((payload_len == 3) && (packet->payload[0] == 0x05) && (packet->payload[1] == 0x01) && (packet->payload[2] == 0x00)) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Possible SOCKS5 request detected, we will look further for the response...\n");

      /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
      flow->socks5_stage = packet->packet_direction + 1;
    }

  } else {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "SOCKS5 stage %u: \n", flow->socks5_stage);

    /* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
    if ((flow->socks5_stage - packet->packet_direction) == 1) {
      return;
    }

    /* This is a packet in another direction. Check if we find the proper response. */
    if ((payload_len == 0) || ((payload_len == 2) && (packet->payload[0] == 0x05) && (packet->payload[1] == 0x00))) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found SOCKS5.\n");
      flow->ndpi_result_base = NDPI_RESULT_BASE_SOCKS5;
      flow->ndpi_excluded_base[NDPI_RESULT_BASE_SOCKS5] = 1;
    } else {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to SOCKS5, resetting the stage to 0...\n");
      flow->socks5_stage = 0;
    }

  }
}

void ndpi_search_socks5(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "SOCKS5 detection...\n");

  ndpi_check_socks5(ndpi_struct, flow);
}

void ndpi_register_proto_socks5 (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {1080, 0, 0, 0, 0};
  int udp_ports[5] = {1080, 0, 0, 0, 0};

  ndpi_initialize_scanner_base (ndpi_mod, NDPI_RESULT_BASE_SOCKS5, "SOCKSv5", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_socks5);
}
