/*
 * tds.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-15 - ntop.org
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
#ifdef NDPI_PROTOCOL_TDS

static void ndpi_int_tds_add_connection(struct ndpi_detection_module_struct
										  *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TDS, NDPI_REAL_PROTOCOL);
}

void ndpi_search_tds_tcp(struct ndpi_detection_module_struct
						   *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	if (packet->payload_packet_len > 8
		&& packet->payload_packet_len < 512
		&& packet->payload[1] < 0x02
		&& ntohs(get_u_int16_t(packet->payload, 2)) == packet->payload_packet_len && get_u_int16_t(packet->payload, 4) == 0x0000) {

		if (flow->l4.tcp.tds_stage == 0) {
			if (packet->payload[0] != 0x02 && packet->payload[0] != 0x07 && packet->payload[0] != 0x12) {
				goto exclude_tds;
			} else {
				flow->l4.tcp.tds_stage = 1 + packet->packet_direction;
				flow->l4.tcp.tds_login_version = packet->payload[0];
				return;
			}
		} else if (flow->l4.tcp.tds_stage == 2 - packet->packet_direction) {
			switch (flow->l4.tcp.tds_login_version) {
			case 0x12:
				if (packet->payload[0] == 0x04) {
					flow->l4.tcp.tds_stage = 3 + packet->packet_direction;
					return;
				} else {
					goto exclude_tds;
				}
				//TODO: add more cases for other versions
			default:
				goto exclude_tds;
			}
		} else if (flow->l4.tcp.tds_stage == 4 - packet->packet_direction) {
			switch (flow->l4.tcp.tds_login_version) {
			case 0x12:
				if (packet->payload[0] == 0x12) {
					NDPI_LOG(NDPI_PROTOCOL_TDS, ndpi_struct, NDPI_LOG_DEBUG, "TDS detected\n");
					ndpi_int_tds_add_connection(ndpi_struct, flow);
					return;
				} else {
					goto exclude_tds;
				}
				//TODO: add more cases for other versions
			default:
				goto exclude_tds;
			}
		}
	}

  exclude_tds:

	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_TDS);
}

#endif
