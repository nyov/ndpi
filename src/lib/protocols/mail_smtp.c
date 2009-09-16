/*
 * mail_smtp.c
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

#ifdef IPOQUE_PROTOCOL_MAIL_SMTP

#define SMTP_BIT_220		0x01
#define SMTP_BIT_250		0x02
#define SMTP_BIT_235		0x04
#define SMTP_BIT_334		0x08
#define SMTP_BIT_354		0x10
#define SMTP_BIT_HELO_EHLO	0x20
#define SMTP_BIT_MAIL		0x40
#define SMTP_BIT_RCPT		0x80
#define SMTP_BIT_AUTH		0x100
#define SMTP_BIT_STARTTLS	0x200
#define SMTP_BIT_DATA		0x400
#define SMTP_BIT_NOOP		0x800
#define SMTP_BIT_RSET		0x1000
#define SMTP_BIT_TlRM		0x2000

static void ipoque_int_mail_smtp_add_connection(struct ipoque_detection_module_struct
												*ipoque_struct)
{

	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
	struct ipoque_id_struct *src = ipoque_struct->src;
	struct ipoque_id_struct *dst = ipoque_struct->dst;

	flow->detected_protocol = IPOQUE_PROTOCOL_MAIL_SMTP;
	packet->detected_protocol = IPOQUE_PROTOCOL_MAIL_SMTP;

	if (src != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(src->detected_protocol_bitmask, IPOQUE_PROTOCOL_MAIL_SMTP);
	}
	if (dst != NULL) {
		IPOQUE_ADD_PROTOCOL_TO_BITMASK(dst->detected_protocol_bitmask, IPOQUE_PROTOCOL_MAIL_SMTP);
	}
}

void ipoque_search_mail_smtp_tcp(struct ipoque_detection_module_struct
								 *ipoque_struct)
{
	struct ipoque_packet_struct *packet = &ipoque_struct->packet;
	struct ipoque_flow_struct *flow = ipoque_struct->flow;
//  struct ipoque_id_struct         *src=ipoque_struct->src;
//  struct ipoque_id_struct         *dst=ipoque_struct->dst;


	IPQ_LOG(IPOQUE_PROTOCOL_MAIL_SMTP, ipoque_struct, IPQ_LOG_DEBUG, "search mail_smtp.\n");

	if (packet->payload_packet_len > 2 && ntohs(get_u16(packet->payload, packet->payload_packet_len - 2)) == 0x0d0a) {

		u8 a = 0;
		u8 bit_count = 0;

		ipq_parse_packet_line_info(ipoque_struct);
		for (a = 0; a < packet->parsed_lines; a++) {

			// expected server responses
			if (packet->line[a].len > 3) {
				if (memcmp(packet->line[a].ptr, "220", 3) == 0) {
					flow->smtp_command_bitmask |= SMTP_BIT_220;
				} else if (memcmp(packet->line[a].ptr, "250", 3) == 0) {
					flow->smtp_command_bitmask |= SMTP_BIT_250;
				} else if (memcmp(packet->line[a].ptr, "235", 3) == 0) {
					flow->smtp_command_bitmask |= SMTP_BIT_235;
				} else if (memcmp(packet->line[a].ptr, "334", 3) == 0) {
					flow->smtp_command_bitmask |= SMTP_BIT_334;
				} else if (memcmp(packet->line[a].ptr, "354", 3) == 0) {
					flow->smtp_command_bitmask |= SMTP_BIT_354;
				}
			}
			// expected client requests
			if (packet->line[a].len > 5) {
				if (memcmp(packet->line[a].ptr, "HELO ", 5) == 0 || memcmp(packet->line[a].ptr, "helo ", 5) == 0 ||
					memcmp(packet->line[a].ptr, "EHLO ", 5) == 0 || memcmp(packet->line[a].ptr, "ehlo ", 5) == 0) {
					flow->smtp_command_bitmask |= SMTP_BIT_HELO_EHLO;
				} else if (memcmp(packet->line[a].ptr, "MAIL ", 5) == 0 || memcmp(packet->line[a].ptr, "mail ", 5) == 0) {
					flow->smtp_command_bitmask |= SMTP_BIT_MAIL;
				} else if (memcmp(packet->line[a].ptr, "RCPT ", 5) == 0 || memcmp(packet->line[a].ptr, "rcpt ", 5) == 0) {
					flow->smtp_command_bitmask |= SMTP_BIT_RCPT;
				} else if (memcmp(packet->line[a].ptr, "AUTH ", 5) == 0 || memcmp(packet->line[a].ptr, "auth ", 5) == 0) {
					flow->smtp_command_bitmask |= SMTP_BIT_AUTH;
				}
			}

			if (packet->line[a].len > 8) {
				if (memcmp(packet->line[a].ptr, "STARTTLS", 8) == 0 || memcmp(packet->line[a].ptr, "starttls", 8) == 0) {
					flow->smtp_command_bitmask |= SMTP_BIT_STARTTLS;
				}
			}

			if (packet->line[a].len > 4) {
				if (memcmp(packet->line[a].ptr, "DATA", 4) == 0 || memcmp(packet->line[a].ptr, "data", 4) == 0) {
					flow->smtp_command_bitmask |= SMTP_BIT_DATA;
				} else if (memcmp(packet->line[a].ptr, "NOOP", 4) == 0 || memcmp(packet->line[a].ptr, "noop", 4) == 0) {
					flow->smtp_command_bitmask |= SMTP_BIT_NOOP;
				} else if (memcmp(packet->line[a].ptr, "RSET", 4) == 0 || memcmp(packet->line[a].ptr, "rset", 4) == 0) {
					flow->smtp_command_bitmask |= SMTP_BIT_RSET;
				}
			}

		}

		// now count the bits set in the bitmask
		for (a = 0; a < 16; a++) {
			bit_count += (flow->smtp_command_bitmask >> a) & 0x01;
		}
		IPQ_LOG(IPOQUE_PROTOCOL_MAIL_SMTP, ipoque_struct, IPQ_LOG_DEBUG, "seen smtp commands and responses: %u.\n",
				bit_count);

		if (bit_count >= 3) {
			IPQ_LOG(IPOQUE_PROTOCOL_MAIL_SMTP, ipoque_struct, IPQ_LOG_DEBUG, "mail smtp identified\n");
			ipoque_int_mail_smtp_add_connection(ipoque_struct);
			return;
		}
	}
	IPQ_LOG(IPOQUE_PROTOCOL_MAIL_SMTP, ipoque_struct, IPQ_LOG_DEBUG, "exclude smtp\n");
	IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, IPOQUE_PROTOCOL_MAIL_SMTP);

}
#endif
