/*
 * imesh.c
 * Copyright (C) 2009 by ipoque GmbH
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

#ifdef IPOQUE_PROTOCOL_IMESH


static void ipoque_int_imesh_add_connection(struct ipoque_detection_module_struct
											*ipoque_struct)
{

	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	flow->detected_protocol = IPOQUE_PROTOCOL_IMESH;
	packet->detected_protocol = IPOQUE_PROTOCOL_IMESH;

	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_IMESH);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_IMESH);
	}
}


void ipoque_search_imesh_tcp_udp(struct ipoque_detection_module_struct
								 *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;


	if (packet->detected_protocol == IPOQUE_PROTOCOL_IMESH) {
		if (src != NULL) {
			src->imesh_timer = packet->tick_timestamp;
		}
		if (dst != NULL) {
			dst->imesh_timer = packet->tick_timestamp;
		}
		return;
	}

	/* skip marked packets */
	if (packet->detected_protocol != IPOQUE_PROTOCOL_UNKNOWN)
		goto imesh_not_found_end;

	if (packet->udp != NULL) {

		IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_DEBUG, "UDP FOUND\n");
		// this is the login packet
		if (					//&& ((IPOQUE_TIMESTAMP_COUNTER_SIZE)(packet->tick_timestamp - src->imesh_timer)) < ipoque_struct->imesh_connection_timeout
			   packet->payload_packet_len == 28 && (get_l32(packet->payload, 0)) == 0x00000002	// PATTERN : 02 00 00 00
			   && (get_l32(packet->payload, 24)) == 0x00000000	// PATTERN : 00 00 00 00
			   && packet->udp->dest == htons(1864)) {
			IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_DEBUG, "iMesh Login detected\n");
			if (src != NULL) {
				src->imesh_timer = packet->tick_timestamp;
			}
			if (dst != NULL) {
				dst->imesh_timer = packet->tick_timestamp;
			}
			ipoque_int_imesh_add_connection(ipoque_struct);
			return;
		} else if (				//&& ((IPOQUE_TIMESTAMP_COUNTER_SIZE)(packet->tick_timestamp - src->imesh_timer)) < ipoque_struct->imesh_connection_timeout
					  packet->payload_packet_len == 36 && (get_l32(packet->payload, 0)) == 0x00000002	// PATTERN : 02 00 00 00
					  //&& packet->payload[35]==0x0f
			) {
			IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_DEBUG, "iMesh detected\n");
			if (src != NULL) {
				if (((IPOQUE_TIMESTAMP_COUNTER_SIZE)
					 (packet->tick_timestamp - src->imesh_timer)) < ipoque_struct->imesh_connection_timeout) {
					src->imesh_timer = packet->tick_timestamp;
					ipoque_int_imesh_add_connection(ipoque_struct);
				}
			}
			if (dst != NULL) {
				if (((IPOQUE_TIMESTAMP_COUNTER_SIZE)
					 (packet->tick_timestamp - dst->imesh_timer)) < ipoque_struct->imesh_connection_timeout) {
					dst->imesh_timer = packet->tick_timestamp;
					ipoque_int_imesh_add_connection(ipoque_struct);
				}
			}
			return;
		}

		IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_DEBUG,
				"iMesh UDP packetlen: %d\n", packet->payload_packet_len);

	} else if (packet->tcp != NULL) {

		IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_DEBUG,
				"TCP FOUND :: Payload %u\n", packet->payload_packet_len);

		if (flow->imesh_stage == 0) {
			// this is the first package to the server
			// we could implement a stage because the replay from the server is also
			// 10 bytes long --> the only difference is that the packet has at [6] == 1 instead of 0
			if (packet->payload_packet_len == 10
				&& get_l32(packet->payload, 0) == 0x00040006
				&& get_l32(packet->payload, 4) == 0x00000000 && get_l16(packet->payload, 8) == 0x0000
				//&& packet->tcp->dest == htons(8080)
				) {
				IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_TRACE,
						"iMesh central server connection detected\n");
				flow->imesh_stage = 1 + packet->packet_direction;
				//ipoque_int_imesh_add_connection(ipoque_struct);
				return;
			} else if (packet->payload_packet_len == 12 && get_l32(packet->payload, 0) == 0x00060006	// PATTERN : 06 00 06 00 00 00 64 00
					   && get_l32(packet->payload, 4) == 0x00640000) {

				IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_TRACE,
						"iMesh First Packet detected :: Payload %u\n", packet->payload_packet_len);

				flow->imesh_stage = 1 + packet->packet_direction;
				return;

			} else if ((packet->payload_packet_len == 64 || packet->payload_packet_len == 52)
					   && get_l16(packet->payload, 0) == (packet->payload_packet_len)
					   && get_l32(packet->payload, 1) == 0x00000000) {

				IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_TRACE,
						"iMesh new type 1 at stage 0: Payload %u\n", packet->payload_packet_len);
				flow->imesh_stage = 1 + packet->packet_direction;
				return;
			} else if (packet->payload_packet_len == 6	// PATTERN : 06 00 04 00 00 00
					   && get_l32(packet->payload, 0) == 0x00040006 && get_l16(packet->payload, 4) == 0x0000) {
				IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_TRACE,
						"iMesh new divided server login at stage 0: Payload %u\n", packet->payload_packet_len);
				flow->imesh_stage = 7 + packet->packet_direction;
				return;
			}
		} else if ((2 - packet->packet_direction) == flow->imesh_stage) {
			if (packet->payload_packet_len == 10
				&& get_l32(packet->payload, 0) == 0x00040006
				&& get_l32(packet->payload, 4) == 0x00010000 && get_l16(packet->payload, 8) == 0x0000
				//&& packet->tcp->dest == htons(8080)
				) {

				IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_TRACE,
						"iMesh central server connection detected (finish)\n");
				if (src != NULL) {
					src->imesh_timer = packet->tick_timestamp;
				}
				if (dst != NULL) {
					dst->imesh_timer = packet->tick_timestamp;
				}
				ipoque_int_imesh_add_connection(ipoque_struct);
				return;
			} else if (packet->payload_packet_len == 95 && get_l16(packet->payload, 0) == (packet->payload_packet_len)
					   && get_l32(packet->payload, 1) == 0x00000000) {
				flow->imesh_stage = 3 + packet->packet_direction;
				return;
			} else if (packet->payload_packet_len >= 300 && packet->payload_packet_len <= 400) {

				IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_TRACE,
						"iMesh Second Packet detected :: Payload %u\n", packet->payload_packet_len);

				flow->imesh_stage = 3 + packet->packet_direction;
				return;
			} else if (packet->payload_packet_len == 6 && get_l16(packet->payload, 0) == (packet->payload_packet_len)
					   && get_l32(packet->payload, 2) == 0xee000000) {
				if (src != NULL) {
					src->imesh_timer = packet->tick_timestamp;
				}
				if (dst != NULL) {
					dst->imesh_timer = packet->tick_timestamp;
				}
				ipoque_int_imesh_add_connection(ipoque_struct);
				return;
			}
		} else if ((4 - packet->packet_direction) == flow->imesh_stage) {
			if ((packet->payload_packet_len == 26
				 || packet->payload_packet_len == 29 || packet->payload_packet_len == 31)
				&& get_l16(packet->payload, 0) == (packet->payload_packet_len)) {

				IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_TRACE, "iMesh download detected\n");
				if (src != NULL) {
					src->imesh_timer = packet->tick_timestamp;
				}
				if (dst != NULL) {
					dst->imesh_timer = packet->tick_timestamp;
				}
				ipoque_int_imesh_add_connection(ipoque_struct);
				return;

			} else if (packet->payload_packet_len >= 200 && packet->payload_packet_len <= 400) {

				IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_TRACE,
						"iMesh Third Packet detected :: Payload %u\n", packet->payload_packet_len);

				flow->imesh_stage = 5 + packet->packet_direction;
				return;
			}
		} else if ((6 - packet->packet_direction) == flow->imesh_stage) {
			if (packet->payload_packet_len == 24	// PATTERN :: 06 00 12 00 00 00 34 00 00
				&& get_l32(packet->payload, 0) == 0x00120006
				&& get_l32(packet->payload, 4) == 0x00340000 && packet->payload[8] == 0x00) {

				IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_TRACE,
						"iMesh Fourth Packet detected :: Payload %u\n", packet->payload_packet_len);

				if (src != NULL) {
					src->imesh_timer = packet->tick_timestamp;
				}
				if (dst != NULL) {
					dst->imesh_timer = packet->tick_timestamp;
				}
				ipoque_int_imesh_add_connection(ipoque_struct);
				return;
			} else if (packet->payload_packet_len == 8	// PATTERN :: 06 00 02 00 00 00 33 00
					   && get_l32(packet->payload, 0) == 0x00020006 && get_l32(packet->payload, 4) == 0x00330000) {

				IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_TRACE,
						"iMesh Fourth Packet detected :: Payload %u\n", packet->payload_packet_len);

				if (src != NULL) {
					src->imesh_timer = packet->tick_timestamp;
				}
				if (dst != NULL) {
					dst->imesh_timer = packet->tick_timestamp;
				}
				ipoque_int_imesh_add_connection(ipoque_struct);
				return;
			}
		} else if ((7 + packet->packet_direction) == flow->imesh_stage) {
			if (packet->payload_packet_len == 4 && get_l32(packet->payload, 0) == 0x00000000) {

				IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_TRACE,
						"NULL packet :: Payload %u\n", packet->payload_packet_len);

				flow->imesh_stage = 9 + packet->packet_direction;
				return;
			}
		} else if ((10 - packet->packet_direction) == flow->imesh_stage) {
			if (packet->payload_packet_len == 10
				&& get_l32(packet->payload, 0) == 0x00040006 && get_l32(packet->payload, 4) == 0x00010000
				/* && packet->payload[8]==0x00 */
				&& packet->payload[9] == 0x00) {

				IPQ_LOG(IPOQUE_PROTOCOL_IMESH, ipoque_struct, IPQ_LOG_TRACE,
						"10 byte type 3 packet :: Payload %u\n", packet->payload_packet_len);

				if (src != NULL) {
					src->imesh_timer = packet->tick_timestamp;
				}
				if (dst != NULL) {
					dst->imesh_timer = packet->tick_timestamp;
				}
				ipoque_int_imesh_add_connection(ipoque_struct);
				return;
			}
		}
	}

  imesh_not_found_end:
	IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_IMESH);
}
#endif
