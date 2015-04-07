/*
 * proto_msn.c
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

#define MAX_PACKETS_FOR_MSN 100

static u_int8_t ndpi_int_find_xmsn(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  if (packet->parsed_lines > 3) {
    u_int16_t i;
    for (i = 2; i < packet->parsed_lines; i++) {
      if (packet->line[i].ptr != NULL && packet->line[i].len > NDPI_STATICSTRING_LEN("X-MSN") &&
	  memcmp(packet->line[i].ptr, "X-MSN", NDPI_STATICSTRING_LEN("X-MSN")) == 0) {
	return 1;
      }
    }
  }
  
  return 0;
}


static void ndpi_search_msn_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
	
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  u_int16_t plen;
  u_int16_t status = 0;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "search msn tcp.\n");

  if (flow->ndpi_result_base == NDPI_RESULT_BASE_SSL) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "msn ssl ft test\n");

    if (flow->packet_counter == 7 && packet->payload_packet_len > 300) {
      if (memcmp(packet->payload + 24, "MSNSLP", 6) == 0
	  || (get_u_int32_t(packet->payload, 0) == htonl(0x30000000) && get_u_int32_t(packet->payload, 4) == 0x00000000)) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "detected MSN File Transfer, ifdef ssl.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
	return;
      }
    }
    
    if (flow->packet_counter >= 5 && flow->packet_counter <= 10 && (get_u_int32_t(packet->payload, 0) == htonl(0x18000000)
								    && get_u_int32_t(packet->payload, 4) == 0x00000000)) {
      flow->l4.tcp.msn_ssl_ft++;
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE,
	       "increased msn ft ssl stage to: %u at packet nr: %u\n", flow->l4.tcp.msn_ssl_ft, flow->packet_counter);
      
      if (flow->l4.tcp.msn_ssl_ft == 2) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE,
		 "detected MSN File Transfer, ifdef ssl 2.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
      }
      
      return;
    }
  }
  
  /* we detect the initial connection only ! */
  /* match: "VER " ..... "CVR" x 0x0d 0x0a
   * len should be small, lets say less than 100 bytes
   * x is now "0", but can be increased
   */
  /* now we have a look at the first packet only. */
  if (flow->packet_counter == 1 || ((flow->ndpi_result_base == NDPI_RESULT_BASE_SSL) && flow->packet_counter <= 3)) {

    /* this part is working asymmetrically */
    if (packet->payload_packet_len > 32 && (packet->payload[0] == 0x02 || packet->payload[0] == 0x00)
	&& (ntohl(get_u_int32_t(packet->payload, 8)) == 0x2112a442 || ntohl(get_u_int32_t(packet->payload, 4)) == 0x2112a442)
	&& ((ntohl(get_u_int32_t(packet->payload, 24)) == 0x000f0004 && ntohl(get_u_int32_t(packet->payload, 28)) == 0x72c64bc6)
	    || (ntohl(get_u_int32_t(packet->payload, 20)) == 0x000f0004
		&& ntohl(get_u_int32_t(packet->payload, 24)) == 0x72c64bc6))) {
      
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "found MSN in packets that also contain voice.messenger.live.com.\n");

      /* TODO this is an alternative pattern for video detection */
      /*          if (packet->payload_packet_len > 100 &&
		  get_u_int16_t(packet->payload, 86) == htons(0x05dc)) { */
      flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;

      return;
    }

    /* this case works asymmetrically */
    if (packet->payload_packet_len > 10 && packet->payload_packet_len < 100) {
      if (get_u_int8_t(packet->payload, packet->payload_packet_len - 2) == 0x0d
	  && get_u_int8_t(packet->payload, packet->payload_packet_len - 1) == 0x0a) {
	/* The MSNP string is used in XBOX clients. */
	if (memcmp(packet->payload, "VER ", 4) == 0) {

	  if (memcmp(&packet->payload[packet->payload_packet_len - 6], "CVR",
		     3) == 0 || memcmp(&packet->payload[packet->payload_packet_len - 8], "MSNP", 4) == 0) {
	    NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE,
		     "found MSN by pattern VER...CVR/MSNP ODOA.\n");
	    flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
	    flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
	    return;
	  }
	  if (memcmp(&packet->payload[4], "MSNFT", 5) == 0) {
	    NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE,
		     "found MSN FT by pattern VER MSNFT...0d0a.\n");
	    flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
	    flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
	    return;
	  }
	}
      }
    }

    if (flow->ndpi_result_base == NDPI_RESULT_BASE_HTTP ||
	memcmp(packet->payload, "GET ", NDPI_STATICSTRING_LEN("GET ")) == 0 ||
	memcmp(packet->payload, "POST ", NDPI_STATICSTRING_LEN("POST ")) == 0) {
      
      ndpi_parse_packet_line_info(ndpi_struct, flow);
    
      if (packet->user_agent_line.ptr != NULL &&
	  packet->user_agent_line.len > NDPI_STATICSTRING_LEN("Messenger/") &&
	  memcmp(packet->user_agent_line.ptr, "Messenger/", NDPI_STATICSTRING_LEN("Messenger/")) == 0) {
	flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
	return;
      }
    }

    /* not seen this pattern in any trace */
    /* now test for http login, at least 100 a bytes packet */
    if (packet->payload_packet_len > 100) {
      if (flow->ndpi_result_base == NDPI_RESULT_BASE_HTTP || memcmp(packet->payload, "POST http://", 12) == 0) {
	
	/* scan packet if not already done... */
	ndpi_parse_packet_line_info(ndpi_struct, flow);

	if (packet->content_line.ptr != NULL &&
	    ((packet->content_line.len == NDPI_STATICSTRING_LEN("application/x-msn-messenger") && memcmp(packet->content_line.ptr, "application/x-msn-messenger",
	      NDPI_STATICSTRING_LEN("application/x-msn-messenger")) == 0) || (packet->content_line.len >= NDPI_STATICSTRING_LEN("text/x-msnmsgr") &&
	      memcmp(packet->content_line.ptr, "text/x-msnmsgr",  NDPI_STATICSTRING_LEN("text/x-msnmsgr")) == 0))) {
	  
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "found MSN by pattern POST http:// .... application/x-msn-messenger.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
	  return;
	}
      }
    }

    /* now test for http login that uses a gateway, at least 400 a bytes packet */
    /* for this case the asymmetric detection is asym (1) */
    if (packet->payload_packet_len > 400) {
      if ((flow->ndpi_result_base == NDPI_RESULT_BASE_HTTP || (memcmp(packet->payload, "POST ", 5) == 0))) {
	
	u_int16_t c;
	
	if (memcmp(&packet->payload[5], "http://", 7) == 0) {
	  /*
	   * We are searching for a paten "POST http://gateway.messenger.hotmail.com/gateway/gateway.dll" or
	   * "POST http://<some ip addres here like 172.0.0.0>/gateway/gateway.dll"
	   * POST http:// is 12 byte so we are searching for 13 to 70 byte for this paten.
	   */
	  for (c = 13; c < 50; c++) {
	    if (memcmp(&packet->payload[c], "/", 1) == 0) {
	      if (memcmp(&packet->payload[c], "/gateway/gateway.dll", 20) == 0) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "found  pattern http://.../gateway/gateway.ddl.\n");
		status = 1;
		break;
	      }
	    }
	  }
	} else if ((memcmp(&packet->payload[5], "/gateway/gateway.dll", 20) == 0)) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "found  pattern http://.../gateway/gateway.ddl.\n");
	  status = 1;
	}
      }
      
      if (status) {
	
	u_int16_t a;

	ndpi_parse_packet_line_info(ndpi_struct, flow);

	if (packet->content_line.ptr != NULL
	    &&
	    ((packet->content_line.len == 23
	      && memcmp(packet->content_line.ptr, "text/xml; charset=utf-8", 23) == 0)
	     ||
	     (packet->content_line.len == 24
	      && memcmp(packet->content_line.ptr, "text/html; charset=utf-8", 24) == 0)
	     ||
	     (packet->content_line.len == 33
	      && memcmp(packet->content_line.ptr, "application/x-www-form-urlencoded", 33) == 0)
	     )) {
	  
	  for (a = 0; a < packet->parsed_lines; a++) {
	    if (packet->line[a].len >= 4 && (memcmp(packet->line[a].ptr, "CVR ", 4) == 0 || memcmp(packet->line[a].ptr, "VER ", 4) == 0 || memcmp(packet->line[a].ptr, "ANS ", 4) == 0)) {
	      NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "found MSN with pattern text/sml; charset0utf-8.\n");
	      NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "MSN xml CVS / VER / ANS found\n");
	      flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
	      flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
	      return;
	    }
	  }
	}
      }
    }
    
    /* asym (1) ; possibly occurs in symmetric cases also. */
    if (flow->packet_counter <= 10 && (flow->packet_direction_counter[0] <= 2 || flow->packet_direction_counter[1] <= 2) && packet->payload_packet_len > 100) {
      /* not necessary to check the length, because this has been done : >400. */
      if (flow->ndpi_result_base == NDPI_RESULT_BASE_HTTP || (memcmp(packet->payload, "HTTP/1.0 200 OK", 15) == 0) || (memcmp(packet->payload, "HTTP/1.1 200 OK", 15) == 0)) {

	ndpi_parse_packet_line_info(ndpi_struct, flow);

	if (packet->content_line.ptr != NULL && ((packet->content_line.len == NDPI_STATICSTRING_LEN("application/x-msn-messenger") &&
	      memcmp(packet->content_line.ptr, "application/x-msn-messenger", NDPI_STATICSTRING_LEN("application/x-msn-messenger")) == 0) ||
	     (packet->content_line.len >= NDPI_STATICSTRING_LEN("text/x-msnmsgr") && memcmp(packet->content_line.ptr, "text/x-msnmsgr", NDPI_STATICSTRING_LEN("text/x-msnmsgr")) == 0))) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "HTTP/1.0 200 OK .... application/x-msn-messenger.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
	  return;
	}
	
	if (ndpi_int_find_xmsn(ndpi_struct, flow) == 1) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "HTTP/1.0 200 OK .... X-MSN.\n");
	  flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
	  return;
	}
      }
    }

    /* did not find any trace with this pattern !!!!! */
    /* now block proxy connection */
    if (packet->payload_packet_len >= 42) {
      if (memcmp(packet->payload, "CONNECT messenger.hotmail.com:1863 HTTP/1.", 42) == 0) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "found MSN  with pattern CONNECT messenger.hotmail.com:1863 HTTP/1..\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
	return;
      }
    }

    if (packet->payload_packet_len >= 18) {

      if (memcmp(packet->payload, "USR ", 4) == 0 || memcmp(packet->payload, "ANS ", 4) == 0) {
	/* now we must see a number */
	const u_int16_t endlen = packet->payload_packet_len - 12;
	plen = 4;
	
	while (1) {
	  if (packet->payload[plen] == ' ') {
	    break;
	  }
	  
	  if (packet->payload[plen] < '0' || packet->payload[plen] > '9') {
	    goto ndpi_msn_exclude;
	  }
	  
	  plen++;
	  
	  if (plen >= endlen) {
	    goto ndpi_msn_exclude;
	  }
	}

	while (plen < endlen) {
	  if (ndpi_check_for_email_address(ndpi_struct, flow, plen) != 0) {
	    NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "found mail address\n");
	    break;
	  }
	  
	  if (packet->payload_packet_len > plen + 1
	      && (packet->payload[plen] < 20 || packet->payload[plen] > 128)) {
	    goto ndpi_msn_exclude;
	  }
	  
	  plen++;
	  
	  if (plen >= endlen) {
	    goto ndpi_msn_exclude;
	  }

	}
	
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "found MSN  with pattern USR/ANS ...mail_address.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
	return;
      }
    }
  }

  /* finished examining the first packet only. */

  /* asym (1) ; possibly occurs in symmetric cases also. */
  if (flow->packet_counter <= 10 && (flow->packet_direction_counter[0] <= 2 || flow->packet_direction_counter[1] <= 2) && packet->payload_packet_len > 100) {
    /* not necessary to check the length, because this has been done : >400. */
    if (flow->ndpi_result_base == NDPI_RESULT_BASE_HTTP || (memcmp(packet->payload, "HTTP/1.0 200 OK", 15) == 0) || (memcmp(packet->payload, "HTTP/1.1 200 OK", 15) == 0)) {

      ndpi_parse_packet_line_info(ndpi_struct, flow);

      if (packet->content_line.ptr != NULL && ((packet->content_line.len == NDPI_STATICSTRING_LEN("application/x-msn-messenger") &&
	    memcmp(packet->content_line.ptr, "application/x-msn-messenger", NDPI_STATICSTRING_LEN("application/x-msn-messenger")) == 0) ||
	   (packet->content_line.len >= NDPI_STATICSTRING_LEN("text/x-msnmsgr") && memcmp(packet->content_line.ptr, "text/x-msnmsgr", NDPI_STATICSTRING_LEN("text/x-msnmsgr")) == 0))) {
	
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "HTTP/1.0 200 OK .... application/x-msn-messenger.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
	return;
      }
      
      if (ndpi_int_find_xmsn(ndpi_struct, flow) == 1) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "HTTP/1.0 200 OK .... X-MSN.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
	return;
      }
    }
  }

  /* MSN File Transfer of MSN 8.1 and 8.5
   * first packet with length 4 and pattern 0x04000000
   * second packet (in the same direction), with length 56 and pattern 0x00000000 from payload[16]
   * third packet (in the opposite direction to 1 & 2), with length 4 and pattern 0x30000000
   */
  if (flow->l4.tcp.msn_stage == 0) {
    
    /* asymmetric detection to this pattern is asym (2) */
    if ((packet->payload_packet_len == 4 || packet->payload_packet_len == 8) && get_u_int32_t(packet->payload, 0) == htonl(0x04000000)) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe first TCP MSN detected\n");

      if (packet->payload_packet_len == 8 && get_u_int32_t(packet->payload, 4) == htonl(0x666f6f00)) {
	flow->l4.tcp.msn_stage = 5 + packet->packet_direction;
	return;
      }

      flow->l4.tcp.msn_stage = 1 + packet->packet_direction;
      return;
    }
    /* asymmetric detection to this pattern is asym (2) */
  } else if (flow->l4.tcp.msn_stage == 1 + packet->packet_direction) {
    
    if (packet->payload_packet_len > 10 && get_u_int32_t(packet->payload, 0) == htonl(0x666f6f00)) {
      flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "MSN File Transfer detected 1\n");
      return;
    }
    
    /* did not see this pattern in any trace */
    if (packet->payload_packet_len == 56 && get_u_int32_t(packet->payload, 16) == 0) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "maybe Second TCP MSN detected\n");
      flow->l4.tcp.msn_stage = 3 + packet->packet_direction;
      return;
    }

  } else if (flow->l4.tcp.msn_stage == 2 - packet->packet_direction && packet->payload_packet_len == 4 && get_u_int32_t(packet->payload, 0) == htonl(0x30000000)) {
    flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "MSN File Transfer detected 2\n");
    return;
  } else if ((flow->l4.tcp.msn_stage == 3 + packet->packet_direction) || (flow->l4.tcp.msn_stage == 4 - packet->packet_direction)) {
    
    if (packet->payload_packet_len == 4 && get_u_int32_t(packet->payload, 0) == htonl(0x30000000)) {
      flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "MSN File Transfer detected 2\n");
      return;
    }
    
  } else if (flow->l4.tcp.msn_stage == 6 - packet->packet_direction) {
    
    if ((packet->payload_packet_len == 4) &&
	(get_u_int32_t(packet->payload, 0) == htonl(0x10000000) || get_u_int32_t(packet->payload, 0) == htonl(0x30000000))) {
      flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "MSN File Transfer detected 3\n");
      return;
    }
    
  } else if (flow->l4.tcp.msn_stage == 5 + packet->packet_direction) {
    if ((packet->payload_packet_len == 20) && get_u_int32_t(packet->payload, 0) == htonl(0x10000000)) {
      flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "MSN File Transfer detected 3\n");
      return;
    }
  }
  
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "msn 7.\n");
  
  if (flow->packet_counter <= MAX_PACKETS_FOR_MSN) {
    if (packet->tcp->source == htons(443) || packet->tcp->dest == htons(443)) {
      if (packet->payload_packet_len > 300) {
	if (memcmp(&packet->payload[40], "INVITE MSNMSGR", 14) == 0  || memcmp(&packet->payload[56], "INVITE MSNMSGR", 14) == 0 || memcmp(&packet->payload[172], "INVITE MSNMSGR", 14) == 0) {
	  flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "MSN File Transfer detected 3\n");
	  return;
	}
      }
      
      return;
    }
    /* For no  n port 443 flows exclude flow bitmask after first packet itself */
  }
  
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "exclude msn.\n");
 ndpi_msn_exclude:
  flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
}

static void ndpi_search_udp_msn_misc(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
	
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  /* asymmetric ft detection works */
  if (packet->payload_packet_len == 20 && get_u_int32_t(packet->payload, 4) == 0 && packet->payload[9] == 0 && get_u_int16_t(packet->payload, 10) == htons(0x0100)) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "msn udp misc data connection detected\n");
    flow->ndpi_result_app = NDPI_RESULT_APP_MSN;
    flow->ndpi_excluded_app[NDPI_RESULT_APP_MSN] = 1;
  }

  /* asymmetric detection working. */
  return;
}

void ndpi_search_msn(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

    /* we deal with tcp now */
    if (packet->tcp != NULL) {
      /* msn can use http or ssl for connection. That's why every http, ssl and ukn packet must enter in the msn detection */
      /* the detection can swich out the http or the ssl detection. In this case we need not check those protocols */
      // need to do the ceck when protocol == http too (POST /gateway ...)
	ndpi_search_msn_tcp(ndpi_struct, flow);
    } else if (packet->udp != NULL) {
      ndpi_search_udp_msn_misc(ndpi_struct, flow);
    }
}

void ndpi_register_proto_msn (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {1863, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_MSN, "MSN", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_msn);
}
