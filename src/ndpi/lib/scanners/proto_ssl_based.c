/*
 * proto_ssl_based.c
 *
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

void ndpi_search_ssl_based(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;

  u_int16_t sport = ntohs(packet->tcp->source);
  u_int16_t dport = ntohs(packet->tcp->dest);
  
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Enrypted protocols detection...\n");
  
  /* Return if the previous level is still not determined. */
  if ((flow->ndpi_result_base == NDPI_RESULT_BASE_STILL_UNKNOWN) || (flow->ndpi_result_base == NDPI_RESULT_BASE_UNKNOWN)) {
    return;
  }
  
  if ((flow->ndpi_result_base == NDPI_RESULT_BASE_SSL) || (flow->ndpi_result_base == NDPI_RESULT_BASE_SSL_NO_CERT)) {
    if ((sport == 25) || (dport == 25) || (sport == 465) || (dport == 465)) {
      flow->ndpi_result_app = NDPI_RESULT_APP_SMTPS;
    } else if ((sport == 993) || (dport == 993)) {
      flow->ndpi_result_app = NDPI_RESULT_APP_IMAPS;
    } else if ((sport == 995) || (dport == 995)) {
      flow->ndpi_result_app = NDPI_RESULT_APP_POPS;
    }
  }
  
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude ssl-based protocols\n");
  flow->ndpi_excluded_app[NDPI_RESULT_APP_IMAPS] = 1;
  flow->ndpi_excluded_app[NDPI_RESULT_APP_POPS] = 1;
  flow->ndpi_excluded_app[NDPI_RESULT_APP_SMTPS] = 1;
}

void ndpi_register_proto_ssl_based (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {25, 465, 993, 995, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_IMAPS, "IMAPS", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_ssl_based);
  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_POPS, "POP3S", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD, tcp_ports, udp_ports, NULL);
  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_SMTPS, "SMTPS", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD, tcp_ports, udp_ports, NULL);
}
