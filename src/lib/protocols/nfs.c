/*
 * nfs.c
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


#include "ndpi_protocols.h"
#ifdef NDPI_PROTOCOL_NFS

static void ndpi_int_nfs_add_connection(struct ndpi_detection_module_struct
										  *ndpi_struct)
{
	ndpi_int_add_connection(ndpi_struct, NDPI_PROTOCOL_NFS, NDPI_REAL_PROTOCOL);
}

void ndpi_search_nfs(struct ndpi_detection_module_struct *ndpi_struct)
{
	struct ndpi_packet_struct *packet = &ndpi_struct->packet;
	struct ndpi_flow_struct *flow = ndpi_struct->flow;
//      struct ndpi_id_struct         *src=ndpi_struct->src;
//      struct ndpi_id_struct         *dst=ndpi_struct->dst;

	u8 offset = 0;
	if (packet->tcp != NULL)
		offset = 4;

	if (packet->payload_packet_len < (40 + offset))
		goto exclude_nfs;

	NDPI_LOG(NDPI_PROTOCOL_NFS, ndpi_struct, NDPI_LOG_DEBUG, "NFS user match stage 1\n");


	if (offset != 0 && get_u32(packet->payload, 0) != htonl(0x80000000 + packet->payload_packet_len - 4))
		goto exclude_nfs;

	NDPI_LOG(NDPI_PROTOCOL_NFS, ndpi_struct, NDPI_LOG_DEBUG, "NFS user match stage 2\n");

	if (get_u32(packet->payload, 4 + offset) != 0)
		goto exclude_nfs;

	NDPI_LOG(NDPI_PROTOCOL_NFS, ndpi_struct, NDPI_LOG_DEBUG, "NFS user match stage 3\n");

	if (get_u32(packet->payload, 8 + offset) != htonl(0x02))
		goto exclude_nfs;

	NDPI_LOG(NDPI_PROTOCOL_NFS, ndpi_struct, NDPI_LOG_DEBUG, "NFS match stage 3\n");

	if (get_u32(packet->payload, 12 + offset) != htonl(0x000186a5)
		&& get_u32(packet->payload, 12 + offset) != htonl(0x000186a3)
		&& get_u32(packet->payload, 12 + offset) != htonl(0x000186a0))
		goto exclude_nfs;

	NDPI_LOG(NDPI_PROTOCOL_NFS, ndpi_struct, NDPI_LOG_DEBUG, "NFS match stage 4\n");

	if (ntohl(get_u32(packet->payload, 16 + offset)) > 4)
		goto exclude_nfs;

	NDPI_LOG(NDPI_PROTOCOL_NFS, ndpi_struct, NDPI_LOG_DEBUG, "NFS match\n");

	ndpi_int_nfs_add_connection(ndpi_struct);
	return;

  exclude_nfs:
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_NFS);
}

#endif
