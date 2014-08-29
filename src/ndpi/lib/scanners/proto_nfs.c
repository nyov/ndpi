/*
 * proto_nfs.c
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

#include "ndpi_api.h"

void ndpi_search_nfs(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	u_int8_t offset = 0;
	if (packet->tcp != NULL)
		offset = 4;

	if (packet->payload_packet_len < (40 + offset))
		goto exclude_nfs;

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "NFS user match stage 1\n");


	if (offset != 0 && get_u_int32_t(packet->payload, 0) != htonl(0x80000000 + packet->payload_packet_len - 4))
		goto exclude_nfs;

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "NFS user match stage 2\n");

	if (get_u_int32_t(packet->payload, 4 + offset) != 0)
		goto exclude_nfs;

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "NFS user match stage 3\n");

	if (get_u_int32_t(packet->payload, 8 + offset) != htonl(0x02))
		goto exclude_nfs;

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "NFS match stage 3\n");

	if (get_u_int32_t(packet->payload, 12 + offset) != htonl(0x000186a5)
		&& get_u_int32_t(packet->payload, 12 + offset) != htonl(0x000186a3)
		&& get_u_int32_t(packet->payload, 12 + offset) != htonl(0x000186a0))
		goto exclude_nfs;

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "NFS match stage 4\n");

	if (ntohl(get_u_int32_t(packet->payload, 16 + offset)) > 4)
		goto exclude_nfs;

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "NFS match\n");

	flow->ndpi_result_app = NDPI_RESULT_APP_NFS;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_NFS] = 1;
	return;

  exclude_nfs:
	flow->ndpi_excluded_app[NDPI_RESULT_APP_NFS] = 1;
}

void ndpi_register_proto_nfs (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {2049, 0, 0, 0, 0};
  int udp_ports[5] = {2049, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_NFS, "NFS", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_nfs);
}
