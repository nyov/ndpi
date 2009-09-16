/*
 * mail_imap.c
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
#ifdef IPOQUE_PROTOCOL_MAIL_IMAP

static void ipoque_int_mail_imap_add_connection(struct ipoque_detection_module_struct
												*ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	flow->detected_protocol = IPOQUE_PROTOCOL_MAIL_IMAP;
	packet->detected_protocol = IPOQUE_PROTOCOL_MAIL_IMAP;

	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_MAIL_IMAP);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_MAIL_IMAP);
	}
}

void ipoque_search_mail_imap_tcp(struct ipoque_detection_module_struct
								 *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;

	u16 i = 0;
	u16 space_pos = 0;
	u16 command_start = 0;
	u8 saw_command = 0;
	const u8 *command = 0;


	IPQ_LOG(IPOQUE_PROTOCOL_MAIL_IMAP, ipoque_struct, IPQ_LOG_DEBUG, "search IMAP.\n");

	if (packet->payload_packet_len >= 4 && ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) {
		// the DONE command appears without a tag
		if (packet->payload_packet_len == 6 &&
			(memcmp(packet->payload, "done", 4) == 0 || memcmp(packet->payload, "DONE", 4) == 0)) {
			flow->mail_imap_stage += 1;
			saw_command = 1;
		} else {

			// search for the first space character (end of the tag)
			while (i < 20 && i < packet->payload_packet_len) {
				if (i > 0 && packet->payload[i] == ' ') {
					space_pos = i;
					break;
				}
				if (!((packet->payload[i] >= 'a' && packet->payload[i] <= 'z') ||
					  (packet->payload[i] >= 'A' && packet->payload[i] <= 'Z') ||
					  (packet->payload[i] >= '0' && packet->payload[i] <= '9') || packet->payload[i] == '*')) {
					goto imap_excluded;
				}
				i++;
			}
			if (space_pos == 0 || space_pos == (packet->payload_packet_len - 1)) {
				goto imap_excluded;
			}
			// now walk over a possible mail number to the next space
			i++;
			if (i < packet->payload_packet_len && (packet->payload[i] >= '0' && packet->payload[i] <= '9')) {
				while (i < 20 && i < packet->payload_packet_len) {
					if (i > 0 && packet->payload[i] == ' ') {
						space_pos = i;
						break;
					}
					if (!(packet->payload[i] >= '0' && packet->payload[i] <= '9')) {
						goto imap_excluded;
					}
					i++;
				}
				if (space_pos == 0 || space_pos == (packet->payload_packet_len - 1)) {
					goto imap_excluded;
				}
			}

			command_start = space_pos + 1;
			command = &(packet->payload[command_start]);

			if ((command_start + 3) < packet->payload_packet_len) {
				if (memcmp(command, "OK ", 3) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				} else if (memcmp(command, "uid", 3) == 0 || memcmp(command, "UID", 3) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				}
			}
			if ((command_start + 10) < packet->payload_packet_len) {
				if (memcmp(command, "capability", 10) == 0 || memcmp(command, "CAPABILITY", 10) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				}
			}
			if ((command_start + 8) < packet->payload_packet_len) {
				if (memcmp(command, "starttls", 8) == 0 || memcmp(command, "STARTTLS", 8) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				}
			}
			if ((command_start + 5) < packet->payload_packet_len) {
				if (memcmp(command, "login", 5) == 0 || memcmp(command, "LOGIN", 5) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				} else if (memcmp(command, "fetch", 5) == 0 || memcmp(command, "FETCH", 5) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				} else if (memcmp(command, "flags", 5) == 0 || memcmp(command, "FLAGS", 5) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				} else if (memcmp(command, "check", 5) == 0 || memcmp(command, "CHECK", 5) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				}
			}
			if ((command_start + 12) < packet->payload_packet_len) {
				if (memcmp(command, "authenticate", 12) == 0 || memcmp(command, "AUTHENTICATE", 12) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				}
			}
			if ((command_start + 9) < packet->payload_packet_len) {
				if (memcmp(command, "namespace", 9) == 0 || memcmp(command, "NAMESPACE", 9) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				}
			}
			if ((command_start + 4) < packet->payload_packet_len) {
				if (memcmp(command, "lsub", 4) == 0 || memcmp(command, "LSUB", 4) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				} else if (memcmp(command, "list", 4) == 0 || memcmp(command, "LIST", 4) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				} else if (memcmp(command, "noop", 4) == 0 || memcmp(command, "NOOP", 4) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				} else if (memcmp(command, "idle", 4) == 0 || memcmp(command, "IDLE", 4) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				}
			}
			if ((command_start + 6) < packet->payload_packet_len) {
				if (memcmp(command, "select", 6) == 0 || memcmp(command, "SELECT", 6) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				} else if (memcmp(command, "exists", 6) == 0 || memcmp(command, "EXISTS", 6) == 0) {
					flow->mail_imap_stage += 1;
					saw_command = 1;
				}
			}

		}

		if (saw_command == 1) {
			if (flow->mail_imap_stage == 3) {
				IPQ_LOG(IPOQUE_PROTOCOL_MAIL_IMAP, ipoque_struct, IPQ_LOG_DEBUG, "mail imap identified\n");
				ipoque_int_mail_imap_add_connection(ipoque_struct);
				return;
			}
		}
	}

  imap_excluded:

	// skip over possible authentication hashes etc. that cannot be identified as imap commands or responses
	// if the packet count is low enough and at least one command or response was seen before
	if ((packet->payload_packet_len >= 2 && ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a)
		&& flow->packet_counter < 6 && flow->mail_imap_stage >= 1) {
		IPQ_LOG(IPOQUE_PROTOCOL_MAIL_IMAP, ipoque_struct, IPQ_LOG_DEBUG,
				"no imap command or response but packet count < 6 and imap stage >= 1 -> skip\n");
		return;
	}

	IPQ_LOG(IPOQUE_PROTOCOL_MAIL_IMAP, ipoque_struct, IPQ_LOG_DEBUG, "exclude IMAP.\n");
	IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_MAIL_IMAP);
}
#endif
