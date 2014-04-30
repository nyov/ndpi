/*
 * pptp.c
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

#include "ndpi_protocols.h"
#ifdef NDPI_OLD_RESULT_APP_PPTP

static void ndpi_int_pptp_add_connection(struct ndpi_detection_module_struct
										   *ndpi_struct, struct ndpi_flow_struct *flow)
{
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_OLD_RESULT_APP_PPTP, NDPI_REAL_PROTOCOL);
}

void ndpi_search_pptp(struct ndpi_detection_module_struct
						*ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;
	

	// struct ndpi_id_struct *src=ndpi_struct->src;
	// struct ndpi_id_struct *dst=ndpi_struct->dst;

	if (packet->payload_packet_len >= 10 && get_u_int16_t(packet->payload, 0) == htons(packet->payload_packet_len)
		&& get_u_int16_t(packet->payload, 2) == htons(0x0001)	/* message type: control message */
		&&get_u_int32_t(packet->payload, 4) == htonl(0x1a2b3c4d)	/* cookie: correct */
		&&(get_u_int16_t(packet->payload, 8) == htons(0x0001)	/* control type: start-control-connection-request */
		)) {

		NDPI_LOG(NDPI_OLD_RESULT_APP_PPTP, ndpi_struct, NDPI_LOG_DEBUG, "found pptp.\n");
		ndpi_int_pptp_add_connection(ndpi_struct, flow);
		return;
	}

	NDPI_LOG(NDPI_OLD_RESULT_APP_PPTP, ndpi_struct, NDPI_LOG_DEBUG, "exclude pptp.\n");
	NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_OLD_RESULT_APP_PPTP);
}
#endif
