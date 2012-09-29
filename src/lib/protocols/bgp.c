/*
 * bgp.c
 * Copyright (C) 2009-2011 by ipoque GmbH
 * 
 * This file is part of OpenDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * OpenDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * OpenDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with OpenDPI.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */


#include "ipq_protocols.h"
#ifdef NDPI_PROTOCOL_BGP


static void ndpi_int_bgp_add_connection(struct ndpi_detection_module_struct
										  *ndpi_struct)
{

	ndpi_int_add_connection(ndpi_struct, NDPI_PROTOCOL_BGP, NDPI_REAL_PROTOCOL);
}

/* this detection also works asymmetrically */
void ndpi_search_bgp(struct ndpi_detection_module_struct *ndpi_struct)
{
	struct ndpi_packet_struct *packet = &ndpi_struct->packet;
	struct ndpi_flow_struct *flow = ndpi_struct->flow;
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	if (packet->payload_packet_len > 18 &&
		get_u64(packet->payload, 0) == 0xffffffffffffffffULL &&
		get_u64(packet->payload, 8) == 0xffffffffffffffffULL &&
		ntohs(get_u16(packet->payload, 16)) <= packet->payload_packet_len &&
		(packet->tcp->dest == htons(179) || packet->tcp->source == htons(179))
		&& packet->payload[18] < 5) {
		NDPI_LOG(NDPI_PROTOCOL_BGP, ndpi_struct, NDPI_LOG_DEBUG, "BGP detected.\n");
		ndpi_int_bgp_add_connection(ndpi_struct);
		return;
	}

	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_BGP);
}

#endif
