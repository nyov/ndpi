/*
 * proto_soulseek.c
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

void ndpi_search_soulseek(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;
	
	struct ndpi_id_struct *src = flow->src;
	struct ndpi_id_struct *dst = flow->dst;

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Soulseek: search soulseec tcp \n");

	if (dst != NULL && dst->soulseek_listen_port != 0 && dst->soulseek_listen_port == ntohs(packet->tcp->dest)
		&& ((u_int32_t)
			(packet->tick_timestamp - dst->soulseek_last_safe_access_time) <
			ndpi_struct->soulseek_connection_ip_tick_timeout)) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
				"Soulseek: Plain detection on Port : %u packet_tick_timestamp: %u soulseeek_last_safe_access_time: %u soulseek_connection_ip_ticktimeout: %u\n",
				dst->soulseek_listen_port, packet->tick_timestamp,
				dst->soulseek_last_safe_access_time, ndpi_struct->soulseek_connection_ip_tick_timeout);
		flow->ndpi_result_app = NDPI_RESULT_APP_SOULSEEK;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_SOULSEEK] = 1;
		return;
	}

	if (flow->l4.tcp.soulseek_stage == 0) {

		u_int32_t index = 0;

		if (packet->payload_packet_len >= 12 && packet->payload_packet_len < 300 && get_l32(packet->payload, 4) == 1) {
		  
			while (!get_u_int16_t(packet->payload, index + 2) && (index + get_l32(packet->payload, index)) < packet->payload_packet_len - 4) {
				if (get_l32(packet->payload, index) < 8)	/*Minimum soulsek  login msg is 8B */
					break;

				if (index + get_l32(packet->payload, index) + 4 <= index) {
					/* avoid overflow */
					break;
				}

				index += get_l32(packet->payload, index) + 4;
			}
			
			if (index + get_l32(packet->payload, index) ==
				packet->payload_packet_len - 4 && !get_u_int16_t(packet->payload, 10)) {
				/*This structure seems to be soulseek proto */
				index = get_l32(packet->payload, 8) + 12;	// end of "user name"
				
				if ((index + 4) <= packet->payload_packet_len && !get_u_int16_t(packet->payload, index + 2))	// for passwd len
				{
					index += get_l32(packet->payload, index) + 4;	//end of  "Passwd"
					
					if ((index + 4 + 4) <= packet->payload_packet_len && !get_u_int16_t(packet->payload, index + 6))	// to read version,hashlen
					{
						index += get_l32(packet->payload, index + 4) + 8;	// enf of "hash value"
						if (index == get_l32(packet->payload, 0)) {
							NDPI_LOG(0,
									ndpi_struct, NDPI_LOG_DEBUG, "Soulseek Login Detected\n");
							flow->ndpi_result_app = NDPI_RESULT_APP_SOULSEEK;
							flow->ndpi_excluded_app[NDPI_RESULT_APP_SOULSEEK] = 1;
							return;
						}
					}
				}
			}
		}
		
		if (packet->payload_packet_len > 8
			&& packet->payload_packet_len < 200 && get_l32(packet->payload, 0) == packet->payload_packet_len - 4) {
			//Server Messages:
			const u_int32_t msgcode = get_l32(packet->payload, 4);

			if (msgcode == 0x7d) {
				flow->l4.tcp.soulseek_stage = 1 + packet->packet_direction;
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Soulseek Messages Search\n");
				return;
			} else if (msgcode == 0x02 && packet->payload_packet_len == 12) {
				const u_int32_t soulseek_listen_port = get_l32(packet->payload, 8);

				if (src != NULL) {
					src->soulseek_last_safe_access_time = packet->tick_timestamp;

					if (packet->tcp != NULL && src->soulseek_listen_port == 0) {
						src->soulseek_listen_port = soulseek_listen_port;
						NDPI_LOG(0, ndpi_struct,
								NDPI_LOG_DEBUG, "\n Listen Port Saved : %u", src->soulseek_listen_port);
						flow->ndpi_result_app = NDPI_RESULT_APP_SOULSEEK;
						flow->ndpi_excluded_app[NDPI_RESULT_APP_SOULSEEK] = 1;
						return;
					}
				}

			}
			
			//Peer Messages  : Peer Init Message Detection
			if (get_l32(packet->payload, 0) == packet->payload_packet_len - 4) {
				const u_int32_t typelen = get_l32(packet->payload, packet->payload_packet_len - 9);
				const u_int8_t type = packet->payload[packet->payload_packet_len - 5];
				const u_int32_t namelen = get_l32(packet->payload, 5);
				
				if (packet->payload[4] == 0x01 && typelen == 1
					&& namelen <= packet->payload_packet_len
					&& (4 + 1 + 4 + namelen + 4 + 1 + 4) ==
					packet->payload_packet_len && (type == 'F' || type == 'P' || type == 'D')) {
					NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "soulseek detected\n");
					flow->ndpi_result_app = NDPI_RESULT_APP_SOULSEEK;
					flow->ndpi_excluded_app[NDPI_RESULT_APP_SOULSEEK] = 1;
					return;
				}
				
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "1\n");
			}
			
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "3\n");
			
			//Peer Message : Pierce Firewall
			if (packet->payload_packet_len == 9 && get_l32(packet->payload, 0) == 5
				&& packet->payload[4] <= 0x10 && get_u_int32_t(packet->payload, 5) != 0x00000000) {
				flow->l4.tcp.soulseek_stage = 1 + packet->packet_direction;
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "Soulseek Size 9 Pierce Firewall\n");
				return;
			}

		}

		if (packet->payload_packet_len > 25 && packet->payload[4] == 0x01 && !get_u_int16_t(packet->payload, 7) && !get_u_int16_t(packet->payload, 2)) {
			const u_int32_t usrlen = get_l32(packet->payload, 5);

			if (usrlen <= packet->payload_packet_len - 4 + 1 + 4 + 4 + 1 + 4) {
				const u_int32_t typelen = get_l32(packet->payload, 4 + 1 + 4 + usrlen);
				const u_int8_t type = packet->payload[4 + 1 + 4 + usrlen + 4];
				
				if (typelen == 1 && (type == 'F' || type == 'P' || type == 'D')) {
					NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "soulseek detected Pattern command(D|P|F).\n");
					flow->ndpi_result_app = NDPI_RESULT_APP_SOULSEEK;
					flow->ndpi_excluded_app[NDPI_RESULT_APP_SOULSEEK] = 1;
					return;
				}
			}
		}

	} else if (flow->l4.tcp.soulseek_stage == 2 - packet->packet_direction) {
		if (packet->payload_packet_len > 8) {
			if ((packet->payload[0] || packet->payload[1]) && get_l32(packet->payload, 4) == 9) {
				/* 9 is search result */
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "soulseek detected Second Pkt\n");
				flow->ndpi_result_app = NDPI_RESULT_APP_SOULSEEK;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_SOULSEEK] = 1;
				return;
			}
			
			if (get_l32(packet->payload, 0) == packet->payload_packet_len - 4) {
				const u_int32_t msgcode = get_l32(packet->payload, 4);
				
				if (msgcode == 0x03 && packet->payload_packet_len >= 12)	//Server Message : Get Peer Address
				{
					const u_int32_t usrlen = get_l32(packet->payload, 8);
					if (usrlen <= packet->payload_packet_len && 4 + 4 + 4 + usrlen == packet->payload_packet_len) {
						NDPI_LOG(0, ndpi_struct,
								NDPI_LOG_DEBUG, "Soulseek Request Get Peer Address Detected\n");
						flow->ndpi_result_app = NDPI_RESULT_APP_SOULSEEK;
						flow->ndpi_excluded_app[NDPI_RESULT_APP_SOULSEEK] = 1;
						return;
					}
				}
			}
		}

		if (packet->payload_packet_len == 8 && get_l32(packet->payload, 4) == 0x00000004) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "soulseek detected\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_SOULSEEK;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_SOULSEEK] = 1;
			return;
		}

		if (packet->payload_packet_len == 4
			&& get_u_int16_t(packet->payload, 2) == 0x00 && get_u_int16_t(packet->payload, 0) != 0x00) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "soulseek detected\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_SOULSEEK;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_SOULSEEK] = 1;
			return;
		} else if (packet->payload_packet_len == 4) {
			flow->l4.tcp.soulseek_stage = 3;
			return;
		}
	} else if (flow->l4.tcp.soulseek_stage == 1 + packet->packet_direction) {
		if (packet->payload_packet_len > 8) {
			if (packet->payload[4] == 0x03 && get_l32(packet->payload, 5) == 0x00000031) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "soulseek detected Second Pkt with SIGNATURE :: 0x0331000000 \n");
				flow->ndpi_result_app = NDPI_RESULT_APP_SOULSEEK;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_SOULSEEK] = 1;
				return;
			}
		}
	}
	
	if (flow->l4.tcp.soulseek_stage == 3 && packet->payload_packet_len == 8 && !get_u_int32_t(packet->payload, 4)) {

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "soulseek detected bcz of 8B  pkt\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_SOULSEEK;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_SOULSEEK] = 1;
		return;
	}
	
	if (flow->l4.tcp.soulseek_stage && flow->packet_counter < 11) {
	} else {
		flow->ndpi_excluded_app[NDPI_RESULT_APP_SOULSEEK] = 1;
	}
}

void ndpi_register_proto_soulseek (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_SOULSEEK, "Soulseek", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_soulseek);
}
