/*
 * proto_oscar.c
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
#include "ndpi_utils.h"

void ndpi_search_oscar(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  
  if (packet->tcp == NULL) {
    return;
  }
  
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR :: TCP\n");
	
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;
  
  if (packet->payload_packet_len >= 10 && packet->payload[0] == 0x2a) {

    /* if is a oscar connection, 10 bytes long */

    /* OSCAR Connection :: Connection detected at initial packets only
     * +----+----+------+------+---------------+
     * |0x2a|Code|SeqNum|PktLen|ProtcolVersion |
     * +----+----+------+------+---------------+
     * Code 1 Byte : 0x01 Oscar Connection
     * SeqNum and PktLen are 2 Bytes each and ProtcolVersion: 0x00000001
     * */
    if (get_u_int8_t(packet->payload, 1) == 0x01 && get_u_int16_t(packet->payload, 4) == htons(packet->payload_packet_len - 6)
	&& get_u_int32_t(packet->payload, 6) == htonl(0x0000000001)) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR Connection FOUND \n");
      flow->ndpi_result_app = NDPI_RESULT_APP_OSCAR;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_OSCAR] = 1;
      return;
    }

    /* OSCAR IM
     * +----+----+------+------+----------+-----------+
     * |0x2a|Code|SeqNum|PktLen|FNACfamily|FNACsubtype|
     * +----+----+------+------+----------+-----------+
     * Code 1 Byte : 0x02 SNAC Header Code;
     * SeqNum and PktLen are 2 Bytes each
     * FNACfamily   2 Byte : 0x0004 IM Messaging
     * FNACEsubtype 2 Byte : 0x0006 IM Outgoing Message, 0x000c IM Message Acknowledgment
     * */
    if (packet->payload[1] == 0x02 && ntohs(get_u_int16_t(packet->payload, 4)) >=
	packet->payload_packet_len - 6 && get_u_int16_t(packet->payload, 6) == htons(0x0004)
	&& (get_u_int16_t(packet->payload, 8) == htons(0x0006) || get_u_int16_t(packet->payload, 8) == htons(0x000c))) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR IM Detected \n");
      flow->ndpi_result_app = NDPI_RESULT_APP_OSCAR;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_OSCAR] = 1;
      return;
    }
  }

  /* detect http connections */
  if (packet->payload_packet_len >= 18) {
    if ((packet->payload[0] == 'P') && (memcmp(packet->payload, "POST /photo/upload", 18) == 0)) {
      NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct, flow, packet);
      if (packet->host_line.len >= 18 && packet->host_line.ptr != NULL) {
	if (memcmp(packet->host_line.ptr, "lifestream.aol.com", 18) == 0) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR over HTTP found, POST method\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_OSCAR;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_OSCAR] = 1;
	  return;
	}
      }
    }
  }
  
  if (packet->payload_packet_len > 40) {
    if ((packet->payload[0] == 'G') && (memcmp(packet->payload, "GET /", 5) == 0)) {
      if ((memcmp(&packet->payload[5], "aim/fetchEvents?aimsid=", 23) == 0) ||
	  (memcmp(&packet->payload[5], "aim/startSession?", 17) == 0) ||
	  (memcmp(&packet->payload[5], "aim/gromit/aim_express", 22) == 0) ||
	  (memcmp(&packet->payload[5], "b/ss/aolwpaim", 13) == 0) ||
	  (memcmp(&packet->payload[5], "hss/storage/aimtmpshare", 23) == 0)) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR over HTTP found, GET /aim/\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_OSCAR;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_OSCAR] = 1;
	return;
      }

      if ((memcmp(&packet->payload[5], "aim", 3) == 0) || (memcmp(&packet->payload[5], "im", 2) == 0)) {
	NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct, flow, packet);
	if (packet->user_agent_line.len > 15 && packet->user_agent_line.ptr != NULL &&
	    ((memcmp(packet->user_agent_line.ptr, "mobileAIM/", 10) == 0) ||
	     (memcmp(packet->user_agent_line.ptr, "ICQ/", 4) == 0) ||
	     (memcmp(packet->user_agent_line.ptr, "mobileICQ/", 10) == 0) ||
	     (memcmp(packet->user_agent_line.ptr, "AIM%20Free/", NDPI_STATICSTRING_LEN("AIM%20Free/")) == 0) ||
	     (memcmp(packet->user_agent_line.ptr, "AIM/", 4) == 0))) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR over HTTP found\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_OSCAR;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_OSCAR] = 1;
	  return;
	}
      }
      
      NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct, flow, packet);
      
      if (packet->referer_line.ptr != NULL && packet->referer_line.len >= 22) {

	if (memcmp(&packet->referer_line.ptr[packet->referer_line.len - NDPI_STATICSTRING_LEN("WidgetMain.swf")], "WidgetMain.swf", NDPI_STATICSTRING_LEN("WidgetMain.swf")) == 0) {
	  
	  u_int16_t i;
	
	  for (i = 0; i < (packet->referer_line.len - 22); i++) {
	    if (packet->referer_line.ptr[i] == 'a') {
	      if (memcmp(&packet->referer_line.ptr[i + 1], "im/gromit/aim_express", 21) == 0) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR over HTTP found : aim/gromit/aim_express\n");
		flow->ndpi_result_app = NDPI_RESULT_APP_OSCAR;
		flow->ndpi_excluded_app[NDPI_RESULT_APP_OSCAR] = 1;
		return;
	      }
	    }
	  }
	}
      }
    }
    
    if (memcmp(packet->payload, "CONNECT ", 8) == 0) {
      if (memcmp(packet->payload, "CONNECT login.icq.com:443 HTTP/1.", 33) == 0) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR ICQ-HTTP FOUND\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_OSCAR;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_OSCAR] = 1;
	return;
      }
      
      if (memcmp(packet->payload, "CONNECT login.oscar.aol.com:5190 HTTP/1.", 40) == 0) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR AIM-HTTP FOUND\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_OSCAR;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_OSCAR] = 1;
	return;
      }

    }
  }

  if (packet->payload_packet_len > 43 && memcmp(packet->payload, "GET http://http.proxy.icq.com/hello HTTP/1.", 43) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR ICQ-HTTP PROXY FOUND\n");
    flow->ndpi_result_app = NDPI_RESULT_APP_OSCAR;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_OSCAR] = 1;
    return;
  }

  if (packet->payload_packet_len > 46 && memcmp(packet->payload, "GET http://aimhttp.oscar.aol.com/hello HTTP/1.", 46) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR AIM-HTTP PROXY FOUND\n");
    flow->ndpi_result_app = NDPI_RESULT_APP_OSCAR;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_OSCAR] = 1;
    return;
  }

  if (packet->payload_packet_len > 5 && get_u_int32_t(packet->payload, 0) == htonl(0x05010003)) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Maybe OSCAR Picturetransfer\n");
    return;
  }

  if (packet->payload_packet_len == 10 && get_u_int32_t(packet->payload, 0) == htonl(0x05000001) && get_u_int32_t(packet->payload, 4) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Maybe OSCAR Picturetransfer\n");
    return;
  }

  if (packet->payload_packet_len >= 70 &&
      memcmp(&packet->payload[packet->payload_packet_len - 26], "\x67\x00\x65\x00\x74\x00\x43\x00\x61\x00\x74\x00\x61\x00\x6c\x00\x6f\x00\x67", 19) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "OSCAR PICTURE TRANSFER\n");
    flow->ndpi_result_app = NDPI_RESULT_APP_OSCAR;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_OSCAR] = 1;
    return;
  }
  
  if (flow->packet_counter < 3 && packet->payload_packet_len > 11 && (memcmp(packet->payload, "\x00\x37\x04\x4a", 4) || memcmp(packet->payload, "\x00\x0a\x04\x4a",4))) {
    return;
  }

  flow->ndpi_excluded_app[NDPI_RESULT_APP_OSCAR] = 1;
}

void ndpi_register_proto_oscar (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_OSCAR, "Oscar", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_oscar);
}
