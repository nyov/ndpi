/*
 * mail_pop.c
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

#ifdef IPOQUE_PROTOCOL_MAIL_POP

static void ipoque_int_mail_pop_add_connection(struct ipoque_detection_module_struct
											   *ipoque_struct)
{

	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	flow->detected_protocol = IPOQUE_PROTOCOL_MAIL_POP;
	packet->detected_protocol = IPOQUE_PROTOCOL_MAIL_POP;

	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_MAIL_POP);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_MAIL_POP);
	}
}


static int ipoque_int_mail_pop_check_for_client_commands(struct ipoque_detection_module_struct
														 *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
//  struct ipoque_flow_struct       *flow = ipoque_struct->flow;
//  struct ipoque_id_struct         *src=ipoque_struct->src;
//  struct ipoque_id_struct         *dst=ipoque_struct->dst;

	if (packet->payload_packet_len > 4 &&
		(memcmp(packet->payload, "AUTH", 4) == 0 || memcmp(packet->payload, "APOP", 4) == 0 ||
		 memcmp(packet->payload, "USER", 4) == 0 || memcmp(packet->payload, "PASS", 4) == 0 ||
		 memcmp(packet->payload, "CAPA", 4) == 0 || memcmp(packet->payload, "LIST", 4) == 0 ||
		 memcmp(packet->payload, "STAT", 4) == 0)) {
		return 1;
	}
	return 0;
}



void ipoque_search_mail_pop_tcp(struct ipoque_detection_module_struct
								*ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
//  struct ipoque_id_struct         *src=ipoque_struct->src;
//  struct ipoque_id_struct         *dst=ipoque_struct->dst;

	u16 dport = 0;
	u16 sport = 0;


	sport = ntohs(packet->tcp->source);
	dport = ntohs(packet->tcp->dest);


	IPQ_LOG(IPOQUE_PROTOCOL_MAIL_POP, ipoque_struct, IPQ_LOG_DEBUG, "search mail_pop\n");


	if ((packet->payload_packet_len > 3 && memcmp(packet->payload, "+OK", 3) == 0) ||
		(packet->payload_packet_len > 4 && memcmp(packet->payload, "-ERR", 4) == 0) ||
		ipoque_int_mail_pop_check_for_client_commands(ipoque_struct)) {

		if (packet->payload_packet_len > 2 && ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) {

			flow->mail_pop_stage += 1;
			if (flow->mail_pop_stage < 3) {
				IPQ_LOG(IPOQUE_PROTOCOL_MAIL_POP, ipoque_struct, IPQ_LOG_DEBUG, "mail pop stage %d\n",
						flow->mail_pop_stage);
				return;
			}
			if (flow->mail_pop_stage == 3) {
				IPQ_LOG(IPOQUE_PROTOCOL_MAIL_POP, ipoque_struct, IPQ_LOG_DEBUG, "mail pop identified\n");
				ipoque_int_mail_pop_add_connection(ipoque_struct);
				return;
			}

		} else {
			// first part of a split packet
			IPQ_LOG(IPOQUE_PROTOCOL_MAIL_POP, ipoque_struct, IPQ_LOG_DEBUG,
					"mail pop command without line ending -> skip\n");
			return;
		}
	}
	if (((packet->payload_packet_len > 2 && ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a)
		 || flow->mail_pop_stage > 0) && flow->packet_counter < 12) {
		// maybe part of a split pop packet
		IPQ_LOG(IPOQUE_PROTOCOL_MAIL_POP, ipoque_struct, IPQ_LOG_DEBUG, "maybe part of split pop packet -> skip\n");
		return;
	}

	IPQ_LOG(IPOQUE_PROTOCOL_MAIL_POP, ipoque_struct, IPQ_LOG_DEBUG, "exclude pop\n");
	IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_MAIL_POP);
}
#endif
