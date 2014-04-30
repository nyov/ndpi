/*
 * proto_steam.c
 *
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

static void ndpi_check_steam_http(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	u_int32_t payload_len = packet->payload_packet_len;

	
	if (packet->user_agent_line.ptr != NULL && packet->user_agent_line.len >= 23 && memcmp(packet->user_agent_line.ptr, "Valve/Steam HTTP Client", 23) == 0) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found STEAM.\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_STEAM;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_STEAM] = 1;
	}
}

static void ndpi_check_steam_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	u_int32_t payload_len = packet->payload_packet_len;
	
	if (flow->steam_stage == 0) {
	    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "STEAM stage 0: \n");
	    
	    	if (((payload_len == 1) || (payload_len == 4) || (payload_len == 5)) && match_first_bytes(packet->payload, "\x01\x00\x00\x00")) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Possible STEAM request detected, we will look further for the response...\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->steam_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
			return;
		}
		
		if (((payload_len == 1) || (payload_len == 4) || (payload_len == 5)) && (packet->payload[0] == 0x00) && (packet->payload[1] == 0x00) && (packet->payload[2] == 0x00)) {
		  	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Possible STEAM request detected, we will look further for the response...\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->steam_stage = packet->packet_direction + 3; // packet_direction 0: stage 3, packet_direction 1: stage 4
			return;
		}
	} else if ((flow->steam_stage == 1) || (flow->steam_stage == 2)) {
	  	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "STEAM stage %u: \n", flow->steam_stage);

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->steam_stage - packet->packet_direction) == 1) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if (((payload_len == 1) || (payload_len == 4) || (payload_len == 5)) && (packet->payload[0] == 0x00) && (packet->payload[1] == 0x00) && (packet->payload[2] == 0x00)) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found STEAM.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_STEAM;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_STEAM] = 1;
		} else {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to STEAM, resetting the stage to 0...\n");
			flow->steam_stage = 0;
		}
	} else if ((flow->steam_stage == 3) || (flow->steam_stage == 4)) {
	  	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "STEAM stage %u: \n", flow->steam_stage);

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->steam_stage - packet->packet_direction) == 3) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if (((payload_len == 1) || (payload_len == 4) || (payload_len == 5)) && match_first_bytes(packet->payload, "\x01\x00\x00\x00")) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found STEAM.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_STEAM;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_STEAM] = 1;
		} else {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to STEAM, resetting the stage to 0...\n");
			flow->steam_stage = 0;
		}
	}
}

static void ndpi_check_steam_udp1(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	u_int32_t payload_len = packet->payload_packet_len;
	
	if ((payload_len > 0) && match_first_bytes(packet->payload, "VS01")) {
	  	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found STEAM.\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_STEAM;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_STEAM] = 1;
		return;
	}

	/* Check if we so far detected the protocol in the request or not. */
	if (flow->steam_stage1 == 0) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "STEAM stage 0: \n");
		
		if ((payload_len > 0) && match_first_bytes(packet->payload, "\x31\xff\x30\x2e")) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Possible STEAM request detected, we will look further for the response...\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->steam_stage1 = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
			return;
		}
		
		if ((payload_len > 0) && match_first_bytes(packet->payload, "\xff\xff\xff\xff")) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Possible STEAM request detected, we will look further for the response...\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->steam_stage1 = packet->packet_direction + 3; // packet_direction 0: stage 3, packet_direction 1: stage 4
			return;
		}

	} else if ((flow->steam_stage1 == 1) || (flow->steam_stage1 == 2)) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "STEAM stage %u: \n", flow->steam_stage1);

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->steam_stage1 - packet->packet_direction) == 1) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if ((payload_len > 0) && match_first_bytes(packet->payload, "\xff\xff\xff\xff")) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found STEAM.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_STEAM;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_STEAM] = 1;
		} else {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to STEAM, resetting the stage to 0...\n");
			flow->steam_stage1 = 0;
		}
		
	} else if ((flow->steam_stage1 == 3) || (flow->steam_stage1 == 4)) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "STEAM stage %u: \n", flow->steam_stage1);

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->steam_stage1 - packet->packet_direction) == 3) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if ((payload_len > 0) && match_first_bytes(packet->payload, "\x31\xff\x30\x2e")) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found STEAM.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_STEAM;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_STEAM] = 1;
		} else {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to STEAM, resetting the stage to 0...\n");
			flow->steam_stage1 = 0;
		}
		
	}
}

static void ndpi_check_steam_udp2(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	u_int32_t payload_len = packet->payload_packet_len;

	/* Check if we so far detected the protocol in the request or not. */
	if (flow->steam_stage2 == 0) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "STEAM stage 0: \n");
		
		if ((payload_len == 25) && match_first_bytes(packet->payload, "\xff\xff\xff\xff")) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Possible STEAM request detected, we will look further for the response...\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->steam_stage2 = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
		}

	} else {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "STEAM stage %u: \n", flow->steam_stage2);

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->steam_stage2 - packet->packet_direction) == 1) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if ((payload_len == 0) || match_first_bytes(packet->payload, "\xff\xff\xff\xff")) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found STEAM.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_STEAM;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_STEAM] = 1;
		} else {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to STEAM, resetting the stage to 0...\n");
			flow->steam_stage2 = 0;
		}
		
	}
}

static void ndpi_check_steam_udp3(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	u_int32_t payload_len = packet->payload_packet_len;

	/* Check if we so far detected the protocol in the request or not. */
	if (flow->steam_stage3 == 0) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "STEAM stage 0: \n");
		
		if ((payload_len == 4) && (packet->payload[0] == 0x39) && (packet->payload[1] == 0x18) && (packet->payload[2] == 0x00) && (packet->payload[3] == 0x00)) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Possible STEAM request detected, we will look further for the response...\n");

			/* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
			flow->steam_stage3 = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
		}

	} else {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "STEAM stage %u: \n", flow->steam_stage3);

		/* At first check, if this is for sure a response packet (in another direction. If not, do nothing now and return. */
		if ((flow->steam_stage3 - packet->packet_direction) == 1) {
			return;
		}

		/* This is a packet in another direction. Check if we find the proper response. */
		if ((payload_len == 0) || ((payload_len == 8) && (packet->payload[0] == 0x3a) && (packet->payload[1] == 0x18) && (packet->payload[2] == 0x00) && (packet->payload[3] == 0x00))) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found STEAM.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_STEAM;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_STEAM] = 1;
		} else {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "The reply did not seem to belong to STEAM, resetting the stage to 0...\n");
			flow->steam_stage3 = 0;
		}
		
	}
}

void ndpi_search_steam(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	/* Break after 20 packets. */
	if (flow->packet_counter > 20) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude STEAM.\n");
		flow->ndpi_excluded_app[NDPI_RESULT_APP_STEAM] = 1;
		return;
	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "STEAM detection...\n");
	ndpi_check_steam_http(ndpi_struct, flow);
	
	if (flow->ndpi_result_app == NDPI_RESULT_APP_STEAM) {
	    return;
	}

	ndpi_check_steam_tcp(ndpi_struct, flow);
	
	if (flow->ndpi_result_app == NDPI_RESULT_APP_STEAM) {
	    return;
	}
	
	ndpi_check_steam_udp1(ndpi_struct, flow);
	
	if (flow->ndpi_result_app == NDPI_RESULT_APP_STEAM) {
	    return;
	}
	
	ndpi_check_steam_udp2(ndpi_struct, flow);
	
	if (flow->ndpi_result_app == NDPI_RESULT_APP_STEAM) {
	    return;
	}
	
	ndpi_check_steam_udp3(ndpi_struct, flow);
}

void ndpi_register_proto_steam (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_STEAM, "Steam", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_steam);
}
