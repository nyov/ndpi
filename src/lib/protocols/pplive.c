/*
 * pplive.c
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

#ifdef IPOQUE_PROTOCOL_PPLIVE

static void ipoque_int_pplive_add_connection(struct ipoque_detection_module_struct
											 *ipoque_struct)
{

	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	flow->detected_protocol = IPOQUE_PROTOCOL_PPLIVE;
	packet->detected_protocol = IPOQUE_PROTOCOL_PPLIVE;


	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_PPLIVE);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_PPLIVE);
	}
}

void ipoque_search_pplive_tcp_udp(struct ipoque_detection_module_struct
								  *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;


	u16 a;


	IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "search pplive.\n");


	if (packet->udp != NULL) {

		if (src != NULL && src->pplive_vod_cli_port == packet->udp->source
			&& IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_PPLIVE)) {
			if ((IPOQUE_TIMESTAMP_COUNTER_SIZE)
				(packet->tick_timestamp - src->pplive_last_packet_time) < ipoque_struct->pplive_connection_timeout) {
				ipoque_int_pplive_add_connection(ipoque_struct);
				src->pplive_last_packet_time = packet->tick_timestamp;
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "timestamp src.\n");
				return;
			} else {
				src->pplive_vod_cli_port = 0;
				src->pplive_last_packet_time = 0;
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "PPLIVE: VOD port timer reset.\n");
			}
		}

		if (dst != NULL && dst->pplive_vod_cli_port == packet->udp->dest
			&& IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_PPLIVE)) {
			if ((IPOQUE_TIMESTAMP_COUNTER_SIZE)
				(packet->tick_timestamp - dst->pplive_last_packet_time) < ipoque_struct->pplive_connection_timeout) {
				ipoque_int_pplive_add_connection(ipoque_struct);
				dst->pplive_last_packet_time = packet->tick_timestamp;
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "timestamp dst.\n");
				return;
			} else {
				dst->pplive_vod_cli_port = 0;
				dst->pplive_last_packet_time = 0;
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "PPLIVE: VOD port timer reset.\n");
			}
		}

		if ((packet->payload_packet_len >= 76) && ((packet->payload[0] == 0x01) || (packet->payload[0] == 0x18)
												   || (packet->payload[0] == 0x05))
			&& (packet->payload[1] == 0x00)
			&& get_l32(packet->payload, 12) == 0 && (packet->payload[16] == 0 || packet->payload[16] == 1)
			&& (packet->payload[17] == 0) && (packet->payload[24] == 0xac)) {
			IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "found pplive over udp with pattern I.\n");
			ipoque_int_pplive_add_connection(ipoque_struct);
			return;
		}

		if (packet->payload_packet_len > 50 && packet->payload[0] == 0xe9
			&& packet->payload[1] == 0x03 && (packet->payload[3] == 0x00 || packet->payload[3] == 0x01)
			&& packet->payload[4] == 0x98 && packet->payload[5] == 0xab
			&& packet->payload[6] == 0x01 && packet->payload[7] == 0x02) {
			IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "found pplive over udp with pattern II.\n");
			ipoque_int_pplive_add_connection(ipoque_struct);
			return;
		}
		if (flow->packet_counter < 5 && !flow->pplive_stage) {	/* With in 1st 4 packets */
			if ((packet->payload_packet_len >= 90 && packet->payload_packet_len <= 110)
				&& !get_u32(packet->payload, packet->payload_packet_len - 16)) {
				flow->pplive_stage = 2;	/* Now start looking for size(28 | 30) */
			}
			if (68 == packet->payload_packet_len
				&& get_l16(packet->payload, 0) == 0x21 && packet->payload[19] == packet->payload[20]
				&& packet->payload[20] == packet->payload[21]
				&& packet->payload[12] == packet->payload[13]
				&& packet->payload[14] == packet->payload[15]) {
				flow->pplive_stage = 3 + packet->packet_direction;
			}
			IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "need next packet I.\n");
			return;
		}
		if (flow->pplive_stage == 3 + packet->packet_direction) {
			/* Because we are expecting packet in reverese direction.. */
			IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "need next packet II.\n");
			return;
		}
		if (flow->pplive_stage == (4 - packet->packet_direction)
			&& packet->payload_packet_len > 67
			&& (get_l16(packet->payload, 0) == 0x21
				|| (get_l16(packet->payload, 0) == 0x22 && !get_l16(packet->payload, 28)))) {
			if (dst != NULL) {
				dst->pplive_vod_cli_port = packet->udp->dest;
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct,
						IPQ_LOG_DEBUG, "PPLIVE: VOD Port marked %u.\n", ntohs(packet->udp->dest));
				dst->pplive_last_packet_time = packet->tick_timestamp;
			}
			IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "found pplive over udp with pattern III.\n");
			ipoque_int_pplive_add_connection(ipoque_struct);
			return;
		}

		if (flow->pplive_stage == 2) {
			if ((packet->payload_packet_len == 30 && (packet->payload[0] == 2 || packet->payload[0] == 3)
				 && get_l32(packet->payload, 21) == 0x01000000)
				|| (packet->payload_packet_len == 28 && (packet->payload[0] == 1 || packet->payload[0] == 0)
					&& get_l32(packet->payload, 19) == 0x01000000)) {

				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG,
						"found pplive over udp with pattern VI.\n");
				ipoque_int_pplive_add_connection(ipoque_struct);
				return;
			}
			if (flow->packet_counter < 45) {
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "need next packet III.\n");
				return;
			}
		}
	} else if (packet->tcp != NULL) {


		IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG,
				"PPLIVE: TCP found, plen = %d, stage = %d, payload[0] = %x, payload[1] = %x, payload[2] = %x, payload[3] = %x \n",
				packet->payload_packet_len, flow->pplive_stage, packet->payload[0], packet->payload[1],
				packet->payload[2], packet->payload[3]);



		if (src != NULL && src->pplive_vod_cli_port == packet->tcp->source
			&& IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_PPLIVE)) {
			if ((IPOQUE_TIMESTAMP_COUNTER_SIZE)
				(packet->tick_timestamp - src->pplive_last_packet_time) < ipoque_struct->pplive_connection_timeout) {
				ipoque_int_pplive_add_connection(ipoque_struct);
				src->pplive_last_packet_time = packet->tick_timestamp;
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "timestamp src.\n");
				return;
			} else {
				src->pplive_vod_cli_port = 0;
				src->pplive_last_packet_time = 0;
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "PPLIVE: VOD port timer reset.\n");
			}
		}

		if (dst != NULL && dst->pplive_vod_cli_port == packet->tcp->dest
			&& IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_PPLIVE)) {
			if ((IPOQUE_TIMESTAMP_COUNTER_SIZE)
				(packet->tick_timestamp - dst->pplive_last_packet_time) < ipoque_struct->pplive_connection_timeout) {
				ipoque_int_pplive_add_connection(ipoque_struct);
				dst->pplive_last_packet_time = packet->tick_timestamp;
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "timestamp dst.\n");
				return;
			} else {
				dst->pplive_vod_cli_port = 0;
				dst->pplive_last_packet_time = 0;
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "PPLIVE: VOD port timer reset.\n");
			}
		}



		if (packet->payload_packet_len > 20 && packet->payload[0] == 0x00 && packet->payload[1] == 0x00
			&& ntohs(get_u16(packet->payload, 2)) == packet->payload_packet_len - 4) {
			if (packet->payload[4] == 0x21 && packet->payload[5] == 0x00) {
				if ((packet->payload[9] == packet->payload[10]) && (packet->payload[9] == packet->payload[11])) {
					if ((packet->payload[16] == packet->payload[17]) &&
						(packet->payload[16] == packet->payload[18]) && (packet->payload[16] == packet->payload[19])) {
						IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct,
								IPQ_LOG_DEBUG, "PPLIVE: direct server request or response found\n");
						ipoque_int_pplive_add_connection(ipoque_struct);
						return;
					}
				}
			}
		}

		/* Adware in the PPLive Client -> first TCP Packet has length of 4 Bytes -> 2nd TCP Packet has length of 96 Bytes */
		/* or */
		/* Peer-List Requests over TCP -> first Packet has length of 4 Bytes -> 2nd TCP Packet has length of 71 Bytes */
		/* there are different possibilities of the order of the packets */

		IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG,
				"PPLIVE: TCP found, plen = %d, stage = %d, payload[0] = %x, payload[1] = %x, payload[2] = %x, payload[3] = %x \n",
				packet->payload_packet_len, flow->pplive_stage,
				packet->payload[0], packet->payload[1], packet->payload[2], packet->payload[3]);

		/* generic pplive detection (independent of the stage) !!! */
		if (packet->payload_packet_len > 11 && packet->payload[0] == 0x00 && packet->payload[1] == 0x00
			&& packet->payload[2] == 0x00 && (packet->payload[3] == packet->payload_packet_len - 4)) {
			if (packet->payload[4] == 0x21 && packet->payload[5] == 0x00
				&& ((packet->payload[8] == 0x98 && packet->payload[9] == 0xab
					 && packet->payload[10] == 0x01 && packet->payload[11] == 0x02)
				)) {
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct,
						IPQ_LOG_DEBUG, "PPLIVE: direct server request or response found\n");
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG,
						"found pplive over tcp with pattern i.\n");
				ipoque_int_pplive_add_connection(ipoque_struct);
				return;
			}
			if (packet->payload_packet_len > 20) {
				a = 4;
				while (a < 20) {
					if (packet->payload[a] >= '0' && packet->payload[a] <= '9') {
						if (a == 19) {
							IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct,
									IPQ_LOG_DEBUG, "PPLIVE: direct new header format found\n");
							IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG,
									"found pplive over tcp with pattern ii.\n");
							ipoque_int_pplive_add_connection(ipoque_struct);
							return;
						} else {
							a++;
						}
					} else {
						break;
					}
				}
			}
		}

		/* 1st and 2nd (KD: ??????? )Packet of Client is 4 Byte  */
		if (flow->pplive_stage == 0) {
			if (packet->payload_packet_len == 4 && packet->payload[0] > 0x04
				&& packet->payload[1] == 0x00 && packet->payload[2] == 0x00 && packet->payload[3] == 0x00) {
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct,
						IPQ_LOG_DEBUG, "PPLIVE: 4Byte TCP Packet Request found \n");

				/* go to the 2nd Client Packet */
				flow->pplive_stage = 1 + packet->packet_direction;
				flow->pplive_next_packet_size[packet->packet_direction] = packet->payload[0];
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "need next packet i.\n");
				return;
			}
		} else if (flow->pplive_stage == 2 - packet->packet_direction) {
			if (packet->payload_packet_len == 4 && packet->payload[0] > 0x04
				&& packet->payload[1] == 0x00 && packet->payload[2] == 0x00 && packet->payload[3] == 0x00) {
				IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct,
						IPQ_LOG_DEBUG, "PPLIVE: 4Byte TCP Packet Response found \n");

				/* go to the 2nd Client Packet */
				flow->pplive_next_packet_size[packet->packet_direction] = packet->payload[0];
			}
			flow->pplive_stage = 3;
			IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "need next packet ii.\n");
			return;
		} else if (flow->pplive_stage == 1 + packet->packet_direction || flow->pplive_stage == 3) {
			if (packet->payload_packet_len > 7 && flow->pplive_next_packet_size[packet->packet_direction] >= 4) {
				if (packet->payload_packet_len == flow->pplive_next_packet_size[packet->packet_direction]) {

					if (packet->payload[0] == 0xe9 && packet->payload[1] == 0x03
						&& ((packet->payload[4] == 0x98
							 && packet->payload[5] == 0xab && packet->payload[6] == 0x01 && packet->payload[7] == 0x02)
						)) {
						IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct,
								IPQ_LOG_DEBUG, "PPLIVE: two packet response found\n");

						IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG,
								"found pplive over tcp with pattern iii.\n");
						ipoque_int_pplive_add_connection(ipoque_struct);
						return;
					}
					if (packet->payload_packet_len > 16) {
						a = 0;
						while (a < 16) {
							if (packet->payload[a] >= '0' && packet->payload[a] <= '9') {
								if (a == 15) {
									IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG,
											"PPLIVE: new header format found\n");
									IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG,
											"found pplive over tcp with pattern v.\n");
									ipoque_int_pplive_add_connection(ipoque_struct);
									return;
								} else {
									a++;
								}
							} else {
								break;
							}
						}
					}
					if (packet->payload_packet_len > 79
						&& get_u32(packet->payload, packet->payload_packet_len - 9) == 0x00000000
						&& get_u32(packet->payload, packet->payload_packet_len - 5) == 0x00000000) {
						IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG,
								"PPLIVE: Last 8 NULL bytes found.\n");
						IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG,
								"found pplive over tcp with pattern vi.\n");
						ipoque_int_pplive_add_connection(ipoque_struct);
						return;
					}
				}
				if (packet->payload_packet_len > flow->pplive_next_packet_size[packet->packet_direction]) {
					if (packet->payload[0] == 0xe9 && packet->payload[1] == 0x03
						&& packet->payload[4] == 0x98 && packet->payload[5] == 0xab
						&& packet->payload[6] == 0x01 && packet->payload[7] == 0x02) {
						a = flow->pplive_next_packet_size[packet->packet_direction];
						IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "a=%u.\n", a);
						if (packet->payload_packet_len > a + 4
							&& packet->payload[a + 2] == 0x00 && packet->payload[a + 3] == 0x00
							&& packet->payload[a] != 0) {
							a += ((packet->payload[a + 1] << 8) + packet->payload[a] + 4);
							IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "a=%u.\n", a);
							if (packet->payload_packet_len == a) {
								IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG,
										"found pplive over tcp with pattern vii.\n");
								ipoque_int_pplive_add_connection(ipoque_struct);
								return;
							}
							if (packet->payload_packet_len > a + 4
								&& packet->payload[a + 2] == 0x00 && packet->payload[a + 3] == 0x00
								&& packet->payload[a] != 0) {
								a += ((packet->payload[a + 1] << 8) + packet->payload[a] + 4);
								if (packet->payload_packet_len == a) {
									IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG,
											"found pplive over tcp with pattern viii.\n");
									ipoque_int_pplive_add_connection(ipoque_struct);
									return;
								}
							}

						}
					}
				}
			}
		}
	}


	IPQ_LOG(IPOQUE_PROTOCOL_PPLIVE, ipoque_struct, IPQ_LOG_DEBUG, "exclude pplive.\n");
	IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_PPLIVE);
}
#endif
