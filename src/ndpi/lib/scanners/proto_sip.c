/*
 * proto_sip.c
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

#include "ndpi_utils.h"
	
#if !defined(WIN32)
static inline
#else
__forceinline static
#endif
void ndpi_search_sip(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "sip detection...\n");
  struct ndpi_packet_struct *packet = &flow->packet;
  
  const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;


  if (payload_len > 4) {
    /* search for STUN Turn ChannelData Prefix */
    u_int16_t message_len = ntohs(get_u_int16_t(packet->payload, 2));
    if (payload_len - 4 == message_len) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found STUN TURN ChannelData prefix.\n");
      payload_len -= 4;
      packet_payload += 4;
    }
  }

    if (payload_len >= 14) {
	if ((memcmp(packet_payload, "NOTIFY ", 7) == 0 || memcmp(packet_payload, "notify ", 7) == 0)
	    && (memcmp(&packet_payload[7], "SIP:", 4) == 0 || memcmp(&packet_payload[7], "sip:", 4) == 0)) {

	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sip NOTIFY.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_SIP;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_SIP] = 1;
	  return;
	}

	if ((memcmp(packet_payload, "REGISTER ", 9) == 0 || memcmp(packet_payload, "register ", 9) == 0)
	    && (memcmp(&packet_payload[9], "SIP:", 4) == 0 || memcmp(&packet_payload[9], "sip:", 4) == 0)) {

	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sip REGISTER.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_SIP;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_SIP] = 1;
	  return;
	}

	if ((memcmp(packet_payload, "INVITE ", 7) == 0 || memcmp(packet_payload, "invite ", 7) == 0)
	    && (memcmp(&packet_payload[7], "SIP:", 4) == 0 || memcmp(&packet_payload[7], "sip:", 4) == 0)) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sip INVITE.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_SIP;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_SIP] = 1;
	  return;
	}
	
        if (memcmp(packet_payload, "SIP/2.0 ", 8) == 0 || memcmp(packet_payload, "sip/2.0 ", 8) == 0) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sip SIP/2.0 *.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_SIP;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_SIP] = 1;
	  return;
	}

        if ((memcmp(packet_payload, "BYE ", 4) == 0 || memcmp(packet_payload, "bye ", 4) == 0)
	    && (memcmp(&packet_payload[4], "SIP:", 4) == 0 || memcmp(&packet_payload[4], "sip:", 4) == 0)) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sip BYE.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_SIP;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_SIP] = 1;
	  return;
	}

        if ((memcmp(packet_payload, "ACK ", 4) == 0 || memcmp(packet_payload, "ack ", 4) == 0)
	    && (memcmp(&packet_payload[4], "SIP:", 4) == 0 || memcmp(&packet_payload[4], "sip:", 4) == 0)) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sip ACK.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_SIP;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_SIP] = 1;
	  return;
	}

        if ((memcmp(packet_payload, "CANCEL ", 7) == 0 || memcmp(packet_payload, "cancel ", 7) == 0)
	    && (memcmp(&packet_payload[4], "SIP:", 7) == 0 || memcmp(&packet_payload[4], "sip:", 7) == 0)) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sip CANCEL.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_SIP;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_SIP] = 1;
	  return;
	}

	/* Courtesy of Miguel Quesada <mquesadab@gmail.com> */
	if ((memcmp(packet_payload, "OPTIONS ", 8) == 0
	     || memcmp(packet_payload, "options ", 8) == 0)
	    && (memcmp(&packet_payload[8], "SIP:", 4) == 0
		|| memcmp(&packet_payload[8], "sip:", 4) == 0)) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found sip OPTIONS.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_SIP;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_SIP] = 1;
	  return;
	}
      }

  /* add bitmask for tcp only, some stupid udp programs
   * send a very few (< 10 ) packets before invite (mostly a 0x0a0x0d, but just search the first 3 payload_packets here */
  if (packet->udp != NULL && flow->packet_counter < 20) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "need next packet.\n");
    return;
  }
  
  /* for STUN flows we need some more packets */
  if (packet->udp != NULL && flow->ndpi_result_app == NDPI_RESULT_APP_STUN && flow->packet_counter < 40) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "need next STUN packet.\n");
    return;
  }

  if (payload_len == 4 && get_u_int32_t(packet_payload, 0) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe sip. need next packet.\n");
    return;
  }
  
  if (payload_len > 30 && packet_payload[0] == 0x90
      && packet_payload[3] == payload_len - 20 && get_u_int32_t(packet_payload, 4) == 0
      && get_u_int32_t(packet_payload, 8) == 0) {
    flow->sip_yahoo_voice = 1;
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe sip yahoo. need next packet.\n");
  }
  
  if (flow->sip_yahoo_voice && flow->packet_counter < 10) {
    return;
  }

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude sip.\n");
  flow->ndpi_excluded_app[NDPI_RESULT_APP_SIP] = 1;
  return;


}

void ndpi_register_proto_sip (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {5060, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_SIP, "SIP", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_sip);
}
