/*
 * telegram.c
 *
 * Copyright (C) 2014 by Gianluca Costa xplico.org
 * Copyright (C) 2012-15 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
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


#include "ndpi_protocols.h"

#ifdef NDPI_PROTOCOL_TELEGRAM

static void ndpi_int_telegram_add_connection(struct ndpi_detection_module_struct
                                             *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TELEGRAM, NDPI_REAL_PROTOCOL);
  NDPI_LOG(NDPI_PROTOCOL_TELEGRAM, ndpi_struct, NDPI_LOG_TRACE, "TELEGRAM Found.\n");
}


void ndpi_search_telegram(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport /* , sport */;
  
  NDPI_LOG(NDPI_PROTOCOL_TELEGRAM, ndpi_struct, NDPI_LOG_TRACE, "TELEGRAM detection...\n");
  /*
    Telegram
    149.154.164.0 - 149.154.167.255
    149.154.168.0 - 149.154.171.255

    http://myip.ms/view/web_hosting/363906/Telegram_Messenger_Network.html
  */
  if (flow->packet.iph) {
    u_int32_t src = ntohl(flow->packet.iph->saddr);
    u_int32_t dst = ntohl(flow->packet.iph->daddr);

    if (((src >= 2509939712) && (src <= 2509940735))
       || ((dst >= 2509939712) && (dst <= 2509940735))
       || ((src >= 2509940736) && (src <= 2509941759))
       || ((dst >= 2509940736) && (dst <= 2509941759))
       ) {
      ndpi_int_telegram_add_connection(ndpi_struct, flow);
      return;
    }
  }

  if (packet->payload_packet_len == 0)
    return;
  if (packet->tcp != NULL) {
    if (packet->payload_packet_len > 56) {
      dport = ntohs(packet->tcp->dest);
      /* sport = ntohs(packet->tcp->source); */

      if (packet->payload[0] == 0xef && (
          dport == 443 || dport == 80 || dport == 25
        )) {
        if (packet->payload[1] == 0x7f) {
          ndpi_int_telegram_add_connection(ndpi_struct, flow);
        }
        else if (packet->payload[1]*4 <= packet->payload_packet_len - 1) {
          ndpi_int_telegram_add_connection(ndpi_struct, flow);
        }
        return;
      }
    }
  }

  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_TELEGRAM);
}
#endif
