/*
 * proto_syslog.c
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

#include "ndpi_protocols.h"

void ndpi_search_syslog(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  
	struct ndpi_packet_struct *packet = &flow->packet;
	
	u_int8_t i;

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search syslog\n");

	if (packet->payload_packet_len > 20 && packet->payload_packet_len <= 1024 && packet->payload[0] == '<') {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "checked len>20 and <1024 and first symbol=<.\n");
		i = 1;

		for (;;) {
			if (packet->payload[i] < '0' || packet->payload[i] > '9' || i++ > 3) {
				NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "read symbols while the symbol is a number.\n");
				break;
			}
		}

		if (packet->payload[i++] != '>') {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "there is no > following the number.\n");
			flow->ndpi_excluded_app[NDPI_RESULT_APP_SYSLOG] = 1;
			return;
		} else {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "a > following the number.\n");
		}

		if (packet->payload[i] == 0x20) {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "a blank following the >: increment i.\n");
			i++;
		} else {
			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "no blank following the >: do nothing.\n");
		}

		/* check for "last message repeated" */
		if (i + sizeof("last message") - 1 <= packet->payload_packet_len &&
			memcmp(packet->payload + i, "last message", sizeof("last message") - 1) == 0) {

			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found syslog by 'last message' string.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_SYSLOG;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_SYSLOG] = 1;

			return;
		} else if (i + sizeof("snort: ") - 1 <= packet->payload_packet_len &&
				   memcmp(packet->payload + i, "snort: ", sizeof("snort: ") - 1) == 0) {

			/* snort events */

			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found syslog by 'snort: ' string.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_SYSLOG;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_SYSLOG] = 1;

			return;
		}

		if (memcmp(&packet->payload[i], "Jan", 3) != 0
			&& memcmp(&packet->payload[i], "Feb", 3) != 0
			&& memcmp(&packet->payload[i], "Mar", 3) != 0
			&& memcmp(&packet->payload[i], "Apr", 3) != 0
			&& memcmp(&packet->payload[i], "May", 3) != 0
			&& memcmp(&packet->payload[i], "Jun", 3) != 0
			&& memcmp(&packet->payload[i], "Jul", 3) != 0
			&& memcmp(&packet->payload[i], "Aug", 3) != 0
			&& memcmp(&packet->payload[i], "Sep", 3) != 0
			&& memcmp(&packet->payload[i], "Oct", 3) != 0
			&& memcmp(&packet->payload[i], "Nov", 3) != 0 && memcmp(&packet->payload[i], "Dec", 3) != 0) {

			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "no month-shortname following: syslog excluded.\n");
			flow->ndpi_excluded_app[NDPI_RESULT_APP_SYSLOG] = 1;

			return;

		} else {

			NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "a month-shortname following: syslog detected.\n");
			flow->ndpi_result_app = NDPI_RESULT_APP_SYSLOG;
			flow->ndpi_excluded_app[NDPI_RESULT_APP_SYSLOG] = 1;

			return;
		}
	}
	
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "no syslog detected.\n");
	flow->ndpi_excluded_app[NDPI_RESULT_APP_SYSLOG] = 1;
}

void ndpi_register_proto_syslog (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {514, 0, 0, 0, 0};
  int udp_ports[5] = {514, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_SYSLOG, "Syslog", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_syslog);
}
