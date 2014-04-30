/*
 * proto_teamviewer.c
 *
 * Copyright (C) 2012 by Gianluca Costa xplico.org
 * Copyright (C) 2012-13 - ntop.org
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

void ndpi_search_teamview(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
    
    
    if (packet->udp != NULL) {
         if (packet->payload_packet_len > 13) {
             if (packet->payload[0] == 0x00 && packet->payload[11] == 0x17 && packet->payload[12] == 0x24) { /* byte 0 is a counter/seq number, and at the start is 0 */
                flow->l4.udp.teamviewer_stage++;
                if (flow->l4.udp.teamviewer_stage == 4 || 
                    packet->udp->dest == ntohs(5938) || packet->udp->source == ntohs(5938)) {
                    flow->ndpi_result_app = NDPI_RESULT_APP_TEAMVIEWER;
		    flow->ndpi_excluded_app[NDPI_RESULT_APP_TEAMVIEWER] = 1;
                }
                return;
            }
        }
    }
    else if(packet->tcp != NULL) {
        if (packet->payload_packet_len > 2) {
            if (packet->payload[0] == 0x17 && packet->payload[1] == 0x24) {
                flow->l4.udp.teamviewer_stage++;
                if (flow->l4.udp.teamviewer_stage == 4 || 
                    packet->tcp->dest == ntohs(5938) || packet->tcp->source == ntohs(5938)) {
                    flow->ndpi_result_app = NDPI_RESULT_APP_TEAMVIEWER;
		    flow->ndpi_excluded_app[NDPI_RESULT_APP_TEAMVIEWER] = 1;
                }
                return;
            }
            else if (flow->l4.udp.teamviewer_stage) {
                if (packet->payload[0] == 0x11 && packet->payload[1] == 0x30) {
                    flow->l4.udp.teamviewer_stage++;
                    if (flow->l4.udp.teamviewer_stage == 4)
                        flow->ndpi_result_app = NDPI_RESULT_APP_TEAMVIEWER;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_TEAMVIEWER] = 1;
                }
                return;
            }
        }
    }
    
    flow->ndpi_excluded_app[NDPI_RESULT_APP_TEAMVIEWER] = 1;
}

void ndpi_register_proto_teamviewer (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_TEAMVIEWER, "TeamViewer", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_teamview);
}
