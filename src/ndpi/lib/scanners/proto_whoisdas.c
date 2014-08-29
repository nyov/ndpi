/*
 * proto_whoisdas.c
 *
 * Copyright (C) 2013 - ntop.org
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

void ndpi_search_whois_das(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  if ((packet->tcp != NULL) && (
	  ((ntohs(packet->tcp->source) == 43) || (ntohs(packet->tcp->dest) == 43))
	  ||
	  ((ntohs(packet->tcp->source) == 4343) || (ntohs(packet->tcp->dest) == 4343))
	  )
      ) {
    
    if (packet->payload_packet_len > 0) {
      u_int max_len = sizeof(flow->host_server_name)-1;
      u_int i, j;
      
      for (i=strlen((const char *)flow->host_server_name), j=0; (i<max_len) && (j<packet->payload_packet_len); i++, j++) {
	
	if ((packet->payload[j] == '\n') || (packet->payload[j] == '\r')) {
	  break;
	}

	flow->host_server_name[i] = packet->payload[j];
      }

      flow->host_server_name[i] = '\0';

      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "{WHOIS/DAS] %s\n", flow->host_server_name);
    }

    flow->ndpi_result_app = NDPI_RESULT_APP_WHOIS_DAS;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_WHOIS_DAS] = 1;
  } else {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "excluding whois_das at stage %d\n", flow->l4.tcp.whois_das_stage);
    flow->ndpi_excluded_app[NDPI_RESULT_APP_WHOIS_DAS] = 1;
  }
}

void ndpi_register_proto_whoisdas (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_WHOIS_DAS, "Whois-DAS", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_whois_das);
}
