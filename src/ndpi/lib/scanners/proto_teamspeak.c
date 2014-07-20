/*
 * proto_teamspeak.c 
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
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

#include "ndpi_utils.h"
#include "ndpi_protocols.h"

u_int16_t tdport = 0, tsport = 0;
u_int16_t udport = 0, usport = 0;

void ndpi_search_teamspeak(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  
  struct ndpi_packet_struct *packet = &flow->packet;

  if (packet->udp != NULL) {
    usport = ntohs(packet->udp->source), udport = ntohs(packet->udp->dest);
    /* http://www.imfirewall.com/en/protocols/teamSpeak.htm  */
    if (((usport == 9987 || udport == 9987) || (usport == 8767 || udport == 8767)) && packet->payload_packet_len >= 20) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found TEAMSPEAK udp.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_TEAMSPEAK;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_TEAMSPEAK] = 1;
    }
  } else if (packet->tcp != NULL) {
    tsport = ntohs(packet->tcp->source), tdport = ntohs(packet->tcp->dest);
    
    /* https://github.com/Youx/soliloque-server/wiki/Connection-packet */
    if(packet->payload_packet_len >= 20) {
      if (((memcmp(packet->payload, "\xf4\xbe\x03\x00", 4) == 0)) ||
	    ((memcmp(packet->payload, "\xf4\xbe\x02\x00", 4) == 0)) ||
	      ((memcmp(packet->payload, "\xf4\xbe\x01\x00", 4) == 0))) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found TEAMSPEAK tcp.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_TEAMSPEAK;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_TEAMSPEAK] = 1;
      }  /* http://www.imfirewall.com/en/protocols/teamSpeak.htm  */
    } else if ((tsport == 14534 || tdport == 14534) || (tsport == 51234 || tdport == 51234)) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found TEAMSPEAK.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_TEAMSPEAK;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_TEAMSPEAK] = 1;
    }
  }
  
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "TEAMSPEAK excluded.\n");
  flow->ndpi_excluded_app[NDPI_RESULT_APP_TEAMSPEAK] = 1;
  return;
}

void ndpi_register_proto_teamspeak (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_TEAMSPEAK, "TeamSpeak", NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_teamspeak);
}
