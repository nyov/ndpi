/*
 * proto_world_of_warcraft.c
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

#if !defined(WIN32)
static inline
#else
__forceinline static
#endif
u_int8_t ndpi_int_is_wow_port(const u_int16_t port)
{
  if (port == htons(3724) || port == htons(6112) || port == htons(6113) ||
      port == htons(6114) || port == htons(4000) || port == htons(1119)) {
    return 1;
  }
  return 0;
}

void ndpi_search_worldofwarcraft(struct ndpi_detection_module_struct
				 *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Search World of Warcraft.\n");

  if (packet->tcp != NULL) {
    if ((packet->payload_packet_len > NDPI_STATICSTRING_LEN("POST /") &&
	 memcmp(packet->payload, "POST /", NDPI_STATICSTRING_LEN("POST /")) == 0) ||
	(packet->payload_packet_len > NDPI_STATICSTRING_LEN("GET /") &&
	 memcmp(packet->payload, "GET /", NDPI_STATICSTRING_LEN("GET /")) == 0)) {
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      if (packet->user_agent_line.ptr != NULL &&
	  packet->user_agent_line.len == NDPI_STATICSTRING_LEN("Blizzard Web Client") &&
	  memcmp(packet->user_agent_line.ptr, "Blizzard Web Client", NDPI_STATICSTRING_LEN("Blizzard Web Client")) == 0) {
	flow->ndpi_result_app = NDPI_RESULT_APP_WORLDOFWARCRAFT;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_WORLDOFWARCRAFT] = 1;
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "World of Warcraft: Web Client found\n");
	return;
      }
    }
    if (packet->payload_packet_len > NDPI_STATICSTRING_LEN("GET /")
	&& memcmp(packet->payload, "GET /", NDPI_STATICSTRING_LEN("GET /")) == 0) {
      ndpi_parse_packet_line_info(ndpi_struct, flow);
      if (packet->user_agent_line.ptr != NULL && packet->host_line.ptr != NULL
	  && packet->user_agent_line.len > NDPI_STATICSTRING_LEN("Blizzard Downloader")
	  && packet->host_line.len > NDPI_STATICSTRING_LEN("worldofwarcraft.com")
	  && memcmp(packet->user_agent_line.ptr, "Blizzard Downloader",
		    NDPI_STATICSTRING_LEN("Blizzard Downloader")) == 0
	  && memcmp(&packet->host_line.ptr[packet->host_line.len - NDPI_STATICSTRING_LEN("worldofwarcraft.com")],
		    "worldofwarcraft.com", NDPI_STATICSTRING_LEN("worldofwarcraft.com")) == 0) {
	flow->ndpi_result_app = NDPI_RESULT_APP_WORLDOFWARCRAFT;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_WORLDOFWARCRAFT] = 1;
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
		 "World of Warcraft: Web Client found\n");
	return;
      }
    }
    
    if (packet->payload_packet_len == 50 && memcmp(&packet->payload[2], "WORLD OF WARCRAFT CONNECTION",
						   NDPI_STATICSTRING_LEN("WORLD OF WARCRAFT CONNECTION")) == 0) {
      flow->ndpi_result_app = NDPI_RESULT_APP_WORLDOFWARCRAFT;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_WORLDOFWARCRAFT] = 1;
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "World of Warcraft: Login found\n");
      return;
    }
    
    if (packet->tcp->dest == htons(3724) && packet->payload_packet_len < 70
	&& packet->payload_packet_len > 40 && (memcmp(&packet->payload[4], "WoW", 3) == 0 || memcmp(&packet->payload[5], "WoW", 3) == 0)) {
      flow->ndpi_result_app = NDPI_RESULT_APP_WORLDOFWARCRAFT;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_WORLDOFWARCRAFT] = 1;
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "World of Warcraft: Login found\n");
      return;
    }

      if (packet->tcp->source == htons(3724)
	  && packet->payload_packet_len == 8 && get_u_int32_t(packet->payload, 0) == htonl(0x0006ec01)) {
	flow->ndpi_result_app = NDPI_RESULT_APP_WORLDOFWARCRAFT;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_WORLDOFWARCRAFT] = 1;
	NDPI_LOG(0, ndpi_struct,
		 NDPI_LOG_DEBUG, "World of Warcraft: connection detected\n");
	return;
      }

    /* for some well known WoW ports
       check another pattern */
    if (flow->l4.tcp.wow_stage == 0) {
      if (ndpi_int_is_wow_port(packet->tcp->source) &&
	  packet->payload_packet_len >= 14 &&
	  ntohs(get_u_int16_t(packet->payload, 0)) == (packet->payload_packet_len - 2)) {
	if (get_u_int32_t(packet->payload, 2) == htonl(0xec010100)) {

	  NDPI_LOG(0, ndpi_struct,
		   NDPI_LOG_DEBUG, "probably World of Warcraft, waiting for final packet\n");
	  flow->l4.tcp.wow_stage = 2;
	  return;
	} else if (packet->payload_packet_len == 41 &&
		   (get_u_int16_t(packet->payload, 2) == htons(0x0085) ||
		    get_u_int16_t(packet->payload, 2) == htons(0x0034) ||
		    get_u_int16_t(packet->payload, 2) == htons(0x1960))) {
	  NDPI_LOG(0, ndpi_struct,
		   NDPI_LOG_DEBUG, "maybe World of Warcraft, need next\n");
	  flow->l4.tcp.wow_stage = 1;
	  return;
	}
      }
    }

    if (flow->l4.tcp.wow_stage == 1) {
      if (packet->payload_packet_len == 325 &&
	  ntohs(get_u_int16_t(packet->payload, 0)) == (packet->payload_packet_len - 2) &&
	  get_u_int16_t(packet->payload, 4) == 0 &&
	  (get_u_int16_t(packet->payload, packet->payload_packet_len - 3) == htons(0x2331) ||
	   get_u_int16_t(packet->payload, 67) == htons(0x2331)) &&
	  (memcmp
	   (&packet->payload[packet->payload_packet_len - 18],
	    "\x94\xec\xff\xfd\x67\x62\xd4\x67\xfb\xf9\xdd\xbd\xfd\x01\xc0\x8f\xf9\x81", 18) == 0
	   || memcmp(&packet->payload[packet->payload_packet_len - 30],
		     "\x94\xec\xff\xfd\x67\x62\xd4\x67\xfb\xf9\xdd\xbd\xfd\x01\xc0\x8f\xf9\x81", 18) == 0)) {
	flow->ndpi_result_app = NDPI_RESULT_APP_WORLDOFWARCRAFT;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_WORLDOFWARCRAFT] = 1;
	NDPI_LOG(0, ndpi_struct,
		 NDPI_LOG_DEBUG, "World of Warcraft: connection detected\n");
	return;
      }
      
      if (packet->payload_packet_len > 32 &&
	  ntohs(get_u_int16_t(packet->payload, 0)) == (packet->payload_packet_len - 2)) {
	if (get_u_int16_t(packet->payload, 4) == 0) {

	  NDPI_LOG(0, ndpi_struct,
		   NDPI_LOG_DEBUG, "probably World of Warcraft, waiting for final packet\n");
	  flow->l4.tcp.wow_stage = 2;
	  return;
	} else if (get_u_int32_t(packet->payload, 2) == htonl(0x12050000)) {
	  NDPI_LOG(0, ndpi_struct,
		   NDPI_LOG_DEBUG, "probably World of Warcraft, waiting for final packet\n");
	  flow->l4.tcp.wow_stage = 2;
	  return;
	}
      }
    }

    if (flow->l4.tcp.wow_stage == 2) {
      if (packet->payload_packet_len == 4) {
	flow->ndpi_result_app = NDPI_RESULT_APP_WORLDOFWARCRAFT;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_WORLDOFWARCRAFT] = 1;
	NDPI_LOG(0, ndpi_struct,
		 NDPI_LOG_DEBUG, "World of Warcraft: connection detected\n");
	return;
      } else if (packet->payload_packet_len > 4 && packet->payload_packet_len <= 16 && packet->payload[4] == 0x0c) {
	flow->ndpi_result_app = NDPI_RESULT_APP_WORLDOFWARCRAFT;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_WORLDOFWARCRAFT] = 1;
	NDPI_LOG(0, ndpi_struct,
		 NDPI_LOG_DEBUG, "World of Warcraft: connection detected\n");
	return;
      } else if (flow->packet_counter < 3) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "waiting for final packet\n");
	return;
      }
    }
    if (flow->l4.tcp.wow_stage == 0 && packet->tcp->dest == htons(1119)) {
      /* special log in port for battle.net/world of warcraft */

      if (packet->payload_packet_len >= 77 &&
	  get_u_int32_t(packet->payload, 0) == htonl(0x40000aed) && get_u_int32_t(packet->payload, 4) == htonl(0xea070aed)) {

	flow->ndpi_result_app = NDPI_RESULT_APP_WORLDOFWARCRAFT;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_WORLDOFWARCRAFT] = 1;
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "World of Warcraft: connection detected\n");
	return;
      }
    }
  }

  flow->ndpi_excluded_app[NDPI_RESULT_APP_WORLDOFWARCRAFT] = 1;
}

void ndpi_register_proto_world_of_warcraft (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_WORLDOFWARCRAFT, "World_of_Warcraft", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_worldofwarcraft);
}
