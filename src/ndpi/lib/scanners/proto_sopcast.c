/*
 * proto_sopcast.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
 * Copyright (C) 2014-15 Tomasz Bujlow <tomasz@bujlow.com>
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

/**
 * this function checks for sopcast tcp pattern
 *
 * NOTE: if you add more patterns please keep the number of if levels
 * low, it is already complex enough
 */
	
#if !defined(WIN32)
 static inline
#else
__forceinline static
#endif
	 u_int8_t ndpi_int_is_sopcast_tcp(const u_int8_t * payload, const u_int16_t payload_len)
{
	if (payload_len != 54)
		return 0;

	if (payload[2] != payload[3] - 4 && payload[2] != payload[3] + 4)
		return 0;

	if (payload[2] != payload[4] - 1 && payload[2] != payload[4] + 1)
		return 0;

	if (payload[25] != payload[25 + 16 - 1] + 1 && payload[25] != payload[25 + 16 - 1] - 1) {

		if (payload[3] != payload[25] &&
			payload[3] != payload[25] - 4 && payload[3] != payload[25] + 4 && payload[3] != payload[25] - 21) {
			return 0;
		}
	}

	if (payload[4] != payload[28] ||
		payload[28] != payload[30] ||
		payload[30] != payload[31] ||
		get_u_int16_t(payload, 30) != get_u_int16_t(payload, 32) || get_u_int16_t(payload, 32) != get_u_int16_t(payload, 34)) {

		if ((payload[2] != payload[5] - 1 && payload[2] != payload[5] + 1) ||
			payload[2] != payload[25] ||
			payload[4] != payload[28] ||
			payload[4] != payload[31] ||
			payload[4] != payload[32] ||
			payload[4] != payload[33] ||
			payload[4] != payload[34] ||
			payload[4] != payload[35] || payload[4] != payload[30] || payload[2] != payload[36]) {
			return 0;
		}
	}

	if (payload[42] != payload[53])
		return 0;

	if (payload[45] != payload[46] + 1 && payload[45] != payload[46] - 1)
		return 0;

	if (payload[45] != payload[49] || payload[46] != payload[50] || payload[47] != payload[51])
		return 0;

	return 1;
}

static void ndpi_search_sopcast_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{

	struct ndpi_packet_struct *packet = &flow->packet;
	
	if (flow->packet_counter == 1 && packet->payload_packet_len == 54 && get_u_int16_t(packet->payload, 0) == ntohs(0x0036)) {
		if (ndpi_int_is_sopcast_tcp(packet->payload, packet->payload_packet_len)) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sopcast TCP \n");
			flow->ndpi_result_app = NDPI_RESULT_APP_SOPCAST;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_SOPCAST] = 1;
			return;
		}
	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude sopcast TCP.  \n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_SOPCAST] = 1;


}

static void ndpi_search_sopcast_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search sopcast.  \n");


	if (packet->payload_packet_len == 52 && packet->payload[0] == 0xff
		&& packet->payload[1] == 0xff && packet->payload[2] == 0x01
		&& packet->payload[8] == 0x02 && packet->payload[9] == 0xff
		&& packet->payload[10] == 0x00 && packet->payload[11] == 0x2c
		&& packet->payload[12] == 0x00 && packet->payload[13] == 0x00 && packet->payload[14] == 0x00) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sopcast with if I.  \n");
		flow->ndpi_result_app = NDPI_RESULT_APP_SOPCAST;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_SOPCAST] = 1;
		return;
	}
	
	if ((packet->payload_packet_len == 80 || packet->payload_packet_len == 28 || packet->payload_packet_len == 94)
		&& packet->payload[0] == 0x00 && (packet->payload[2] == 0x02 || packet->payload[2] == 0x01)
		&& packet->payload[8] == 0x01 && packet->payload[9] == 0xff
		&& packet->payload[10] == 0x00 && packet->payload[11] == 0x14
		&& packet->payload[12] == 0x00 && packet->payload[13] == 0x00) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sopcast with if II.  \n");
		flow->ndpi_result_app = NDPI_RESULT_APP_SOPCAST;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_SOPCAST] = 1;
		return;
	}
	
	if (packet->payload_packet_len == 60 && packet->payload[0] == 0x00
		&& packet->payload[2] == 0x01
		&& packet->payload[8] == 0x03 && packet->payload[9] == 0xff
		&& packet->payload[10] == 0x00 && packet->payload[11] == 0x34
		&& packet->payload[12] == 0x00 && packet->payload[13] == 0x00 && packet->payload[14] == 0x00) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sopcast with if III.  \n");
		flow->ndpi_result_app = NDPI_RESULT_APP_SOPCAST;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_SOPCAST] = 1;
		return;
	}
	
	if (packet->payload_packet_len == 42 && packet->payload[0] == 0x00
		&& packet->payload[1] == 0x02 && packet->payload[2] == 0x01
		&& packet->payload[3] == 0x07 && packet->payload[4] == 0x03
		&& packet->payload[8] == 0x06
		&& packet->payload[9] == 0x01 && packet->payload[10] == 0x00
		&& packet->payload[11] == 0x22 && packet->payload[12] == 0x00 && packet->payload[13] == 0x00) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sopcast with if IV.  \n");
		flow->ndpi_result_app = NDPI_RESULT_APP_SOPCAST;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_SOPCAST] = 1;
		return;
	}
	
	if (packet->payload_packet_len == 28 && packet->payload[0] == 0x00
		&& packet->payload[1] == 0x0c && packet->payload[2] == 0x01
		&& packet->payload[3] == 0x07 && packet->payload[4] == 0x00
		&& packet->payload[8] == 0x01
		&& packet->payload[9] == 0x01 && packet->payload[10] == 0x00
		&& packet->payload[11] == 0x14 && packet->payload[12] == 0x00 && packet->payload[13] == 0x00) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sopcast with if V.  \n");
		flow->ndpi_result_app = NDPI_RESULT_APP_SOPCAST;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_SOPCAST] = 1;
		return;
	}
	
	if (packet->payload_packet_len == 286 && packet->payload[0] == 0x00
		&& packet->payload[1] == 0x02 && packet->payload[2] == 0x01
		&& packet->payload[3] == 0x07 && packet->payload[4] == 0x03
		&& packet->payload[8] == 0x06
		&& packet->payload[9] == 0x01 && packet->payload[10] == 0x01
		&& packet->payload[11] == 0x16 && packet->payload[12] == 0x00 && packet->payload[13] == 0x00) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sopcast with if VI.  \n");
		flow->ndpi_result_app = NDPI_RESULT_APP_SOPCAST;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_SOPCAST] = 1;
		return;
	}
	
	if (packet->payload_packet_len == 76 && packet->payload[0] == 0xff
		&& packet->payload[1] == 0xff && packet->payload[2] == 0x01
		&& packet->payload[8] == 0x0c && packet->payload[9] == 0xff
		&& packet->payload[10] == 0x00 && packet->payload[11] == 0x44
		&& packet->payload[16] == 0x01 && packet->payload[15] == 0x01
		&& packet->payload[12] == 0x00 && packet->payload[13] == 0x00 && packet->payload[14] == 0x00) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sopcast with if VII.  \n");
		flow->ndpi_result_app = NDPI_RESULT_APP_SOPCAST;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_SOPCAST] = 1;
		return;
	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude sopcast.  \n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_SOPCAST] = 1;
}

void ndpi_search_sopcast(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->udp != NULL)
		ndpi_search_sopcast_udp(ndpi_struct, flow);
	if (packet->tcp != NULL)
		ndpi_search_sopcast_tcp(ndpi_struct, flow);
}

void ndpi_register_proto_sopcast (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_SOPCAST, "Sopcast", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_sopcast);
}
