/*
 * proto_pando.c
 *
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

static void ndpi_check_pando_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	u_int32_t payload_len = packet->payload_packet_len;

	if ((payload_len > 0) && match_first_bytes(packet->payload, "\x0ePan")) {
	    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found PANDO.\n");
	    flow->ndpi_result_app = NDPI_RESULT_APP_PANDO;
	    flow->ndpi_excluded_app[NDPI_RESULT_APP_PANDO] = 1;
	}
}

static void ndpi_check_pando_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	u_int32_t payload_len = packet->payload_packet_len;

	/* Check if we so far detected the protocol in the request or not. */
	if (flow->pando_stage == 0) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "PANDO stage 0: \n");

		if ((payload_len >= 4) && (packet->payload[0] == 0x00) && (packet->payload[1] == 0x00) && (packet->payload[2] == 0x00) && (packet->payload[3] == 0x09)) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Possible PANDO request detected, we will look further for the response...\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->pando_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
			return;
		}
		
		if ((payload_len > 0) && match_first_bytes(packet->payload, "UDPA")) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Possible PANDO request detected, we will look further for the response...\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->pando_stage = packet->packet_direction + 3; // packet_direction 0: stage 3, packet_direction 1: stage 4
			return;
		}
		
		if ((payload_len > 0) && match_first_bytes(packet->payload, "UDPR") || match_first_bytes(packet->payload, "UDPE")) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Possible PANDO request detected, we will look further for the response...\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->pando_stage = packet->packet_direction + 5; // packet_direction 0: stage 5, packet_direction 1: stage 6
			return;
		}

	} else if ((flow->pando_stage == 1) || (flow->pando_stage == 2)) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "PANDO stage %u: \n", flow->pando_stage);

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->pando_stage - packet->packet_direction) == 1) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if ((payload_len == 0) || ((payload_len >= 4) && (packet->payload[0] == 0x00) && (packet->payload[1] == 0x00) && (packet->payload[2] == 0x00) && (packet->payload[3] == 0x09))) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found PANDO.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_PANDO;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_PANDO] = 1;
		} else {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to PANDO, resetting the stage to 0...\n");
			flow->pando_stage = 0;
		}
		
	} else if ((flow->pando_stage == 3) || (flow->pando_stage == 4)) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "PANDO stage %u: \n", flow->pando_stage);

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->pando_stage - packet->packet_direction) == 3) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if ((payload_len == 0) || match_first_bytes(packet->payload, "UDPR") || match_first_bytes(packet->payload, "UDPE")) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found PANDO.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_PANDO;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_PANDO] = 1;
		} else {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to PANDO, resetting the stage to 0...\n");
			flow->pando_stage = 0;
		}
		
	} else if ((flow->pando_stage == 5) || (flow->pando_stage == 6)) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "PANDO stage %u: \n", flow->pando_stage);

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->pando_stage - packet->packet_direction) == 5) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if ((payload_len > 0) && match_first_bytes(packet->payload, "UDPA")) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found PANDO.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_PANDO;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_PANDO] = 1;
		} else {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to PANDO, resetting the stage to 0...\n");
			flow->pando_stage = 0;
		}
	}
}

void ndpi_search_pando(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	/* Break after 20 packets. */
	if (flow->packet_counter > 20) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "PANDO excluded.\n");
		flow->ndpi_excluded_app[NDPI_RESULT_APP_PANDO] = 1;
		return;
	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "PANDO detection...\n");
	ndpi_check_pando_tcp(ndpi_struct, flow);
	
	if (flow->ndpi_result_app == NDPI_RESULT_APP_PANDO) {
	    return;
	}
	
	ndpi_check_pando_udp(ndpi_struct, flow);
}

void ndpi_register_proto_pando (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_PANDO, "Pando_Media_Booster", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_pando);
}
