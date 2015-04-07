/*
 * proto_netbios.c
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

void ndpi_search_netbios(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	u_int16_t dport;

	if (packet->udp != NULL) {
		dport = ntohs(packet->udp->dest);

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "netbios udp start\n");

		/*check standard NETBIOS over udp to port 137  */
		if ((dport == 137 || 0) && packet->payload_packet_len >= 50) {

			NDPI_LOG(0, ndpi_struct,
					NDPI_LOG_DEBUG, "found netbios port 137 and payload_packet_len 50\n");


			if (ntohs(get_u_int16_t(packet->payload, 2)) == 0 &&
				ntohs(get_u_int16_t(packet->payload, 4)) == 1 &&
				ntohs(get_u_int16_t(packet->payload, 6)) == 0 &&
				ntohs(get_u_int16_t(packet->payload, 8)) == 0 && ntohs(get_u_int16_t(packet->payload, 10)) == 0) {

				NDPI_LOG(0, ndpi_struct,
						NDPI_LOG_DEBUG, "found netbios with questions = 1 and answers = 0, authority = 0  \n");

				flow->ndpi_result_app = NDPI_RESULT_APP_NETBIOS;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
				return;
			}
			if (packet->payload[2] == 0x80 &&
				ntohs(get_u_int16_t(packet->payload, 4)) == 1 &&
				ntohs(get_u_int16_t(packet->payload, 6)) == 0 &&
				ntohs(get_u_int16_t(packet->payload, 8)) == 0 && ntohs(get_u_int16_t(packet->payload, 10)) == 1) {

				NDPI_LOG(0, ndpi_struct,
						NDPI_LOG_DEBUG, "found netbios with questions = 1 and answers, authority, additional = 0  \n");

				flow->ndpi_result_app = NDPI_RESULT_APP_NETBIOS;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
				return;
			}
			if (ntohs(get_u_int16_t(packet->payload, 2)) == 0x4000 &&
				ntohs(get_u_int16_t(packet->payload, 4)) == 1 &&
				ntohs(get_u_int16_t(packet->payload, 6)) == 0 &&
				ntohs(get_u_int16_t(packet->payload, 8)) == 0 && ntohs(get_u_int16_t(packet->payload, 10)) == 1) {

				NDPI_LOG(0, ndpi_struct,
						NDPI_LOG_DEBUG, "found netbios with questions = 1 and answers = 0, authority = 0  \n");

				flow->ndpi_result_app = NDPI_RESULT_APP_NETBIOS;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
				return;
			}
			if (ntohs(get_u_int16_t(packet->payload, 2)) == 0x8400 &&
				ntohs(get_u_int16_t(packet->payload, 4)) == 0 &&
				ntohs(get_u_int16_t(packet->payload, 6)) == 1 &&
				ntohs(get_u_int16_t(packet->payload, 8)) == 0 && ntohs(get_u_int16_t(packet->payload, 10)) == 0) {

				NDPI_LOG(0, ndpi_struct,
						NDPI_LOG_DEBUG,
						"found netbios with flag 8400 questions = 0 and answers = 1, authority, additional = 0  \n");

				flow->ndpi_result_app = NDPI_RESULT_APP_NETBIOS;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
				return;
			}
			if (ntohs(get_u_int16_t(packet->payload, 2)) == 0x8500 &&
				ntohs(get_u_int16_t(packet->payload, 4)) == 0 &&
				ntohs(get_u_int16_t(packet->payload, 6)) == 1 &&
				ntohs(get_u_int16_t(packet->payload, 8)) == 0 && ntohs(get_u_int16_t(packet->payload, 10)) == 0) {

				NDPI_LOG(0, ndpi_struct,
						NDPI_LOG_DEBUG,
						"found netbios with flag 8500 questions = 0 and answers = 1, authority, additional = 0  \n");

				flow->ndpi_result_app = NDPI_RESULT_APP_NETBIOS;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
				return;
			}
			if (ntohs(get_u_int16_t(packet->payload, 2)) == 0x2910 &&
				ntohs(get_u_int16_t(packet->payload, 4)) == 1 &&
				ntohs(get_u_int16_t(packet->payload, 6)) == 0 &&
				ntohs(get_u_int16_t(packet->payload, 8)) == 0 && ntohs(get_u_int16_t(packet->payload, 10)) == 1) {

				NDPI_LOG(0, ndpi_struct,
						NDPI_LOG_DEBUG,
						"found netbios with flag 2910, questions = 1 and answers, authority=0, additional = 1  \n");

				flow->ndpi_result_app = NDPI_RESULT_APP_NETBIOS;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
				return;
			}
			if (ntohs(get_u_int16_t(packet->payload, 2)) == 0xAD86 &&
				ntohs(get_u_int16_t(packet->payload, 4)) == 0 &&
				ntohs(get_u_int16_t(packet->payload, 6)) == 1 &&
				ntohs(get_u_int16_t(packet->payload, 8)) == 0 && ntohs(get_u_int16_t(packet->payload, 10)) == 0) {

				NDPI_LOG(0, ndpi_struct,
						NDPI_LOG_DEBUG,
						"found netbios with flag ad86 questions = 0 and answers = 1, authority, additional = 0  \n");

				flow->ndpi_result_app = NDPI_RESULT_APP_NETBIOS;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
				return;
			}
			if (ntohs(get_u_int16_t(packet->payload, 2)) == 0x0110 &&
				ntohs(get_u_int16_t(packet->payload, 4)) == 1 &&
				ntohs(get_u_int16_t(packet->payload, 6)) == 0 &&
				ntohs(get_u_int16_t(packet->payload, 8)) == 0 && ntohs(get_u_int16_t(packet->payload, 10)) == 0) {

				NDPI_LOG(0, ndpi_struct,
						NDPI_LOG_DEBUG,
						"found netbios with flag 0110 questions = 1 and answers = 0, authority, additional = 0  \n");

				flow->ndpi_result_app = NDPI_RESULT_APP_NETBIOS;
				flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
				return;
			}

			if ((ntohs(get_u_int16_t(packet->payload, 2)) & 0xf800) == 0) {

				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "possible netbios name query request\n");

				if (get_u_int16_t(packet->payload, 4) == htons(1) &&
					get_u_int16_t(packet->payload, 6) == 0 &&
					get_u_int16_t(packet->payload, 8) == 0 && get_u_int16_t(packet->payload, 10) == 0) {

					/* name is encoded as described in rfc883 */
					u_int8_t name_length = packet->payload[12];

					NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
							"possible netbios name query request, one question\n");

					if (packet->payload_packet_len == 12 + 1 + name_length + 1 + 2 + 2) {

						NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
								"possible netbios name query request, length matches\n");

						/* null terminated? */
						if (packet->payload[12 + name_length + 1] == 0 &&
							get_u_int16_t(packet->payload, 12 + name_length + 2) == htons(0x0020) &&
							get_u_int16_t(packet->payload, 12 + name_length + 4) == htons(0x0001)) {

							NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
									"found netbios name query request\n");
							flow->ndpi_result_app = NDPI_RESULT_APP_NETBIOS;
							flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
							return;
						}
					}
				}
			} else if ((ntohs(get_u_int16_t(packet->payload, 2)) & 0xf800) == 0x8000) {

				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
						"possible netbios name query response\n");

				if (get_u_int16_t(packet->payload, 4) == 0 &&
					get_u_int16_t(packet->payload, 6) == htons(1) &&
					get_u_int16_t(packet->payload, 8) == 0 && get_u_int16_t(packet->payload, 10) == 0) {

					/* name is encoded as described in rfc883 */
					u_int8_t name_length = packet->payload[12];

					NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
							"possible netbios positive name query response, one answer\n");

					if (packet->payload_packet_len >= 12 + 1 + name_length + 1 + 2 + 2) {

						NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
								"possible netbios name query response, length matches\n");

						/* null terminated? */
						if (packet->payload[12 + name_length + 1] == 0 &&
							get_u_int16_t(packet->payload, 12 + name_length + 2) == htons(0x0020) &&
							get_u_int16_t(packet->payload, 12 + name_length + 4) == htons(0x0001)) {

							NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
									"found netbios name query response\n");
							flow->ndpi_result_app = NDPI_RESULT_APP_NETBIOS;
							flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
							return;
						}
					}
				} else if (get_u_int16_t(packet->payload, 4) == 0 &&
						   get_u_int16_t(packet->payload, 6) == 0 &&
						   get_u_int16_t(packet->payload, 8) == 0 && get_u_int16_t(packet->payload, 10) == 0) {

					/* name is encoded as described in rfc883 */
					u_int8_t name_length = packet->payload[12];

					NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
							"possible netbios negative name query response, one answer\n");

					if (packet->payload_packet_len >= 12 + 1 + name_length + 1 + 2 + 2) {

						NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
								"possible netbios name query response, length matches\n");

						/* null terminated? */
						if (packet->payload[12 + name_length + 1] == 0 &&
							get_u_int16_t(packet->payload, 12 + name_length + 2) == htons(0x000A) &&
							get_u_int16_t(packet->payload, 12 + name_length + 4) == htons(0x0001)) {

							NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
									"found netbios name query response\n");
							flow->ndpi_result_app = NDPI_RESULT_APP_NETBIOS;
							flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
							return;
						}
					}
				} else if (get_u_int16_t(packet->payload, 4) == 0 &&
						   get_u_int16_t(packet->payload, 6) == 0 &&
						   get_u_int16_t(packet->payload, 8) == htons(1) && get_u_int16_t(packet->payload, 10) == htons(1)) {

					/* name is encoded as described in rfc883 */
					u_int8_t name_length = packet->payload[12];

					NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
							"possible netbios redirect name query response, one answer\n");

					if (packet->payload_packet_len >= 12 + 1 + name_length + 1 + 2 + 2) {

						NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
								"possible netbios name query response, length matches\n");

						/* null terminated? */
						if (packet->payload[12 + name_length + 1] == 0 &&
							get_u_int16_t(packet->payload, 12 + name_length + 2) == htons(0x0002) &&
							get_u_int16_t(packet->payload, 12 + name_length + 4) == htons(0x0001)) {

							NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
									"found netbios name query response\n");
							flow->ndpi_result_app = NDPI_RESULT_APP_NETBIOS;
							flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
							return;
						}
					}
				}
			}
			/* TODO: extend according to rfc1002 */
		}



		/*check standard NETBIOS over udp to port 138 */

		/*netbios header token from http://www.protocolbase.net/protocols/protocol_NBDGM.php */

		if ((dport == 138 ||
			 0) &&
			packet->payload_packet_len >= 14 &&
			ntohs(get_u_int16_t(packet->payload, 10)) == packet->payload_packet_len - 14) {

			NDPI_LOG(0, ndpi_struct,
					NDPI_LOG_DEBUG, "found netbios port 138 and payload length >= 112 \n");


			if (packet->payload[0] >= 0x11 && packet->payload[0] <= 0x16) {

				NDPI_LOG(0, ndpi_struct,
						NDPI_LOG_DEBUG, "found netbios with MSG-type 0x11,0x12,0x13,0x14,0x15 or 0x16\n");




				if (ntohl(get_u_int32_t(packet->payload, 4)) == ntohl(packet->iph->saddr)) {
					NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found netbios with checked ip-address.\n");
					flow->ndpi_result_app = NDPI_RESULT_APP_NETBIOS;
					flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
					return;
				}
			}
		}
	}

	if (packet->tcp != NULL) {
		dport = ntohs(packet->tcp->dest);

		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "netbios tcp start\n");

		/* destination port must be 139 */
		if (dport == 139) {

			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found netbios with destination port 139\n");

			/* payload_packet_len must be 72 */
			if (packet->payload_packet_len == 72) {
				NDPI_LOG(0, ndpi_struct,
						NDPI_LOG_DEBUG, "found netbios with payload_packen_len = 72. \n");

				if (packet->payload[0] == 0x81 && packet->payload[1] == 0 && ntohs(get_u_int16_t(packet->payload, 2)) == 68) {
					NDPI_LOG(0, ndpi_struct,
							NDPI_LOG_DEBUG,
							"found netbios with session request = 81, flags=0 and length od following bytes = 68. \n");

					flow->ndpi_result_app = NDPI_RESULT_APP_NETBIOS;
					flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
					return;
				}
			}
		}

	}

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude netbios\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_NETBIOS] = 1;
}

void ndpi_register_proto_netbios (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {139, 0, 0, 0, 0};
  int udp_ports[5] = {137, 138, 139, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_NETBIOS, "NETBIOS", NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_netbios);
}
