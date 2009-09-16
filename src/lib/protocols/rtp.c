/*
 * rtp.c
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
#ifdef IPOQUE_PROTOCOL_RTP

#define RTP_MAX_OUT_OF_ORDER 10

static void ipoque_int_rtp_add_connection(struct ipoque_detection_module_struct
										  *ipoque_struct)
{

	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	flow->detected_protocol = IPOQUE_PROTOCOL_RTP;
	packet->detected_protocol = IPOQUE_PROTOCOL_RTP;

	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_RTP);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_RTP);
	}
}


void ipoque_search_rtp_udp(struct ipoque_detection_module_struct *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	u8 stage = (packet->packet_direction == 0 ? flow->rtp_stage1 : flow->rtp_stage2);
	u8 packet_difference = 0;


	IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct, IPQ_LOG_DEBUG, "search rtp.\n");

	if (packet->payload_packet_len == 1 && packet->payload[0] == 0) {
		IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct, IPQ_LOG_DEBUG,
				"need next packet, payload_packet_len == 1 && payload[0] == 0.\n");
		return;
	}

	if (packet->payload_packet_len < 12) {
		IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct, IPQ_LOG_DEBUG, "minimal packet size for rtp packets: 12.\n");
		goto exclude_rtp;
	}

	if ((packet->payload[0] & 0xc0) != 0x80) {
		IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct,
				IPQ_LOG_DEBUG, "rtp version must be 2, first two bits of a packets must be 10.\n");
		goto exclude_rtp;
	}

	if ((packet->payload[0] & 0x10) != 0x00 && packet->payload_packet_len > 14) {
		IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct,
				IPQ_LOG_DEBUG, "extension rtp packet, rtp connection will start in one of the next packets.\n");
		return;
	}


	if (stage > 0) {
		IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct,
				IPQ_LOG_DEBUG, "stage = %u.\n", packet->packet_direction == 0 ? flow->rtp_stage1 : flow->rtp_stage2);
		if (flow->rtp_ssid[packet->packet_direction] != get_u32(packet->payload, 8)) {
			IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct, IPQ_LOG_DEBUG, "goto exclude rtp I.\n");
			goto exclude_rtp;
		}
		if (ntohs(get_u16(packet->payload, 2)) > flow->rtp_seqnum[packet->packet_direction]) {
			packet_difference = ntohs(get_u16(packet->payload, 2)) - flow->rtp_seqnum[packet->packet_direction];
			if (packet_difference > RTP_MAX_OUT_OF_ORDER) {
				IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct, IPQ_LOG_DEBUG, "goto exclude rtp II.\n");
				goto exclude_rtp;
			}
		} else if (ntohs(get_u16(packet->payload, 2)) < flow->rtp_seqnum[packet->packet_direction]) {
			packet_difference = flow->rtp_seqnum[packet->packet_direction] - ntohs(get_u16(packet->payload, 2));
			if (packet_difference > RTP_MAX_OUT_OF_ORDER) {
				IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct, IPQ_LOG_DEBUG, "goto exclude rtp III.\n");
				goto exclude_rtp;
			}
		} else {
			IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct, IPQ_LOG_DEBUG, "goto exclude rtp IV.\n");
			goto exclude_rtp;
		}
	} else {
		IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct,
				IPQ_LOG_DEBUG, "rtp_ssid[%u] = %u.\n", packet->packet_direction,
				flow->rtp_ssid[packet->packet_direction]);
		flow->rtp_ssid[packet->packet_direction] = get_u32(packet->payload, 8);
		/* the ssid is choosen randonmly. assume that it is not too small, to avoid missdetections.
		 * the chance here that we loose a correct rtp flow with this assumption is 1/1,000.000,000.*/
		if (flow->rtp_ssid[packet->packet_direction] < 8) {
			if (flow->packet_counter < 3) {
			} else {
				goto exclude_rtp;
			}
		}

	}
	IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct,
			IPQ_LOG_DEBUG, " rtp_seqnum[%u] = %u.\n", packet->packet_direction,
			flow->rtp_seqnum[packet->packet_direction]);
	flow->rtp_seqnum[packet->packet_direction] = ntohs(get_u16(packet->payload, 2));

	if (stage == 3) {
		IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct, IPQ_LOG_DEBUG, "add connection I.\n");
		ipoque_int_rtp_add_connection(ipoque_struct);
	} else {
		packet->packet_direction == 0 ? flow->rtp_stage1++ : flow->rtp_stage2++;
		IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct, IPQ_LOG_DEBUG, "need next packet I.\n");
	}
	return;

  exclude_rtp:
#ifdef IPOQUE_PROTOCOL_STUN
	if (packet->detected_protocol == IPOQUE_PROTOCOL_STUN) {
		IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct, IPQ_LOG_DEBUG, "STUN: is detected, need next packet.\n");
		return;
	}
#endif							/*  IPOQUE_PROTOCOL_STUN */
	IPQ_LOG(IPOQUE_PROTOCOL_RTP, ipoque_struct, IPQ_LOG_DEBUG, "exclude rtp.\n");
	IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_RTP);
}

#endif
