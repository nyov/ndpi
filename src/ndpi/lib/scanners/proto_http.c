/*
 * proto_http.c
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

#include "ndpi_api.h"

static void ndpi_int_http_add_connection(struct ndpi_flow_struct *flow, u_int32_t protocol) {
  if (protocol == NDPI_RESULT_BASE_HTTP_CONNECT) {
    flow->ndpi_result_base = NDPI_RESULT_BASE_HTTP_CONNECT;
    return;
  }
  
  if (protocol == NDPI_RESULT_BASE_HTTP_PROXY) {
    flow->ndpi_result_base = NDPI_RESULT_BASE_HTTP_PROXY;
    return;
  }  
  
  if (flow->packet.tcp->dest == htons(8080) || flow->packet.tcp->source == htons(8080) || flow->packet.tcp->dest == htons(3128) || flow->packet.tcp->source == htons(3128)) {
    flow->ndpi_result_base = NDPI_RESULT_BASE_HTTP_PROXY;
  } else {
    flow->ndpi_result_base = NDPI_RESULT_BASE_HTTP;
  }
}

static void setHttpUserAgent(struct ndpi_flow_struct *flow, char *ua) {
  if(!strcmp(ua, "Windows NT 5.0")) ua = "Windows 2000";
  else if(!strcmp(ua, "Windows NT 5.1")) ua = "Windows XP";
  else if(!strcmp(ua, "Windows NT 5.2")) ua = "Windows Server 2003";
  else if(!strcmp(ua, "Windows NT 6.0")) ua = "Windows Vista";
  else if(!strcmp(ua, "Windows NT 6.1")) ua = "Windows 7";
  else if(!strcmp(ua, "Windows NT 6.2")) ua = "Windows 8";
  else if(!strcmp(ua, "Windows NT 6.3")) ua = "Windows 8.1";
  
  snprintf((char*)flow->detected_os, sizeof(flow->detected_os), "%s", ua);  
}

/*
  NOTE

  ndpi_parse_packet_line_info @ ndpi_main.c
  is the code that parses the packet
 */
static void check_content_type_and_change_protocol(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {

  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t a;

  if (packet->content_line.ptr != NULL && packet->content_line.len != 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Content Type Line found %.*s\n", packet->content_line.len, packet->content_line.ptr);
  }

  /* check user agent here too */
  if (packet->user_agent_line.ptr != NULL && packet->user_agent_line.len != 0) {
    /* Format: 
       Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) ....
    */
    if (packet->user_agent_line.len > 7) {
      char ua[256];
      u_int mlen = ndpi_min(packet->user_agent_line.len, sizeof(ua)-1);

      strncpy(ua, (const char *)packet->user_agent_line.ptr, mlen);
      ua[mlen] = '\0';
      
      if(strncmp(ua, "Mozilla", 7) == 0) {
	char *parent = strchr(ua, '(');
	
	if(parent) {
	  char *token, *end;

	  parent++;
	  end = strchr(parent, ')');
	  if(end) end[0] = '\0';
	  
	  token = strsep(&parent, ";");
	  if(token) {
	    if((strcmp(token, "X11") == 0)
	       || (strcmp(token, "compatible") == 0)
	       || (strcmp(token, "Linux") == 0)
	       || (strcmp(token, "Macintosh") == 0)
	       ) {
	      token = strsep(&parent, ";");
	      if(token && (token[0] == ' ')) token++; /* Skip space */
	      
	      if(token 
		 && ((strcmp(token, "U") == 0)
		     || (strncmp(token, "MSIE", 4) == 0))) {
		token = strsep(&parent, ";");
		if(token && (token[0] == ' ')) token++; /* Skip space */

		if(token && (strncmp(token, "Update", 6)  == 0)) {
		  token = strsep(&parent, ";");

		  if(token && (token[0] == ' ')) token++; /* Skip space */
		  
		  if(token && (strncmp(token, "AOL", 3)  == 0)) {
		    token = strsep(&parent, ";");

		    if(token && (token[0] == ' ')) token++; /* Skip space */
		  }
		}
	      }
	    }

	    if (token) {
	      setHttpUserAgent(flow, token);
	    }
	  }
	}
      }
    }

    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "User Agent Type Line found %.*s\n", packet->user_agent_line.len, packet->user_agent_line.ptr);
  }

  /* check for host line */
  if (packet->host_line.ptr != NULL) {
    u_int len;

    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HOST Line found %.*s\n", packet->host_line.len, packet->host_line.ptr);

    /* Copy result for nDPI apps */
    len = ndpi_min(packet->host_line.len, sizeof(flow->host_server_name)-1);
    strncpy((char*)flow->host_server_name, (char*)packet->host_line.ptr, len);
    flow->host_server_name[len] = '\0';
    
    len = ndpi_min(packet->forwarded_line.len, sizeof(flow->nat_ip)-1);
    strncpy((char*)flow->nat_ip, (char*)packet->forwarded_line.ptr, len);
    flow->nat_ip[len] = '\0';
  }
   
  /* check for accept line */
  if (packet->accept_line.ptr != NULL) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Accept Line found %.*s\n", packet->accept_line.len, packet->accept_line.ptr);
  }
}

/**
 * this functions checks whether the packet begins with a valid http request
 * @param ndpi_struct
 * @returnvalue 0 if no valid request has been found
 * @returnvalue >0 indicates start of filename but not necessarily in packet limit
 */
static u_int16_t http_request_url_offset(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "====>>>> HTTP: %c%c%c%c [len: %u]\n",
	   packet->payload[0], packet->payload[1], packet->payload[2], packet->payload[3],
	   packet->payload_packet_len);

  /* FIRST PAYLOAD PACKET FROM CLIENT */
  /* check if the packet starts with POST or GET */
  if (packet->payload_packet_len >= 4 && memcmp(packet->payload, "GET ", 4) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: GET FOUND\n");
    return 4;
  } else if (packet->payload_packet_len >= 5 && memcmp(packet->payload, "POST ", 5) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: POST FOUND\n");
    return 5;
  } else if (packet->payload_packet_len >= 8 && memcmp(packet->payload, "OPTIONS ", 8) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: OPTIONS FOUND\n");
    return 8;
  } else if (packet->payload_packet_len >= 5 && memcmp(packet->payload, "HEAD ", 5) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: HEAD FOUND\n");
    return 5;
  } else if (packet->payload_packet_len >= 4 && memcmp(packet->payload, "PUT ", 4) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: PUT FOUND\n");
    return 4;
  } else if (packet->payload_packet_len >= 7 && memcmp(packet->payload, "DELETE ", 7) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: DELETE FOUND\n");
    return 7;
  } else if (packet->payload_packet_len >= 8 && memcmp(packet->payload, "CONNECT ", 8) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: CONNECT FOUND\n");
    return 8;
  } else if (packet->payload_packet_len >= 9 && memcmp(packet->payload, "PROPFIND ", 9) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: PROFIND FOUND\n");
    return 9;
  } else if (packet->payload_packet_len >= 7 && memcmp(packet->payload, "REPORT ", 7) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: REPORT FOUND\n");
    return 7;
  }

  return 0;
}

static void ndpi_search_http_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t filename_start;
  
  /* Break after 20 packets. */
  if (flow->packet_counter > 20) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude HTTP.\n");
    flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP] = 1;
    flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP_CONNECT] = 1;
    flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP_PROXY] = 1;
    return;
  }

  /* Exclude the scanner if the result is found and it is not HTTP. */
  if (flow->ndpi_result_base != NDPI_RESULT_BASE_STILL_UNKNOWN) {
    if (flow->ndpi_result_base != NDPI_RESULT_BASE_HTTP) {
      if (flow->ndpi_result_base != NDPI_RESULT_BASE_HTTP_CONNECT) {
	if (flow->ndpi_result_base != NDPI_RESULT_BASE_HTTP_PROXY) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude http\n");
	  flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP] = 1;
	  flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP_CONNECT] = 1;
	  flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP_PROXY] = 1;
	}
      }      
    }
  }
  
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search http\n");

  /* Check if we so far detected the protocol in the request or not. */
  if (flow->l4.tcp.http_stage == 0) {
    flow->http_detected = 0;

    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP stage %d: \n", flow->l4.tcp.http_stage);

    filename_start = http_request_url_offset(ndpi_struct, flow);


    if (filename_start == 0) {
      
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Filename HTTP not found, we look for possible truncate flow...\n");
      
      if (packet->payload_packet_len >= 7 && memcmp(packet->payload, "HTTP/1.", 7) == 0) {
        NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP response found (truncated flow ?)\n");
        ndpi_int_http_add_connection(flow, NDPI_RESULT_BASE_HTTP);
        check_content_type_and_change_protocol(ndpi_struct, flow);
        return;
      }

      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude HTTP\n");
      flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP] = 1;
      flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP_CONNECT] = 1;
      flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP_PROXY] = 1;
      return;
    }

    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Filename HTTP found: %d, we look for line info..\n", filename_start);

    ndpi_parse_packet_line_info(ndpi_struct, flow);

    if (packet->parsed_lines <= 1) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found just one line, we will look further for the next packet...\n");

      packet->http_method.ptr = packet->line[0].ptr;
      packet->http_method.len = filename_start - 1;

      /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
      flow->l4.tcp.http_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
      return;
    }

    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found more than one line, we look further for the next packet...\n");

    if (packet->line[0].len >= (9 + filename_start) && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {

      packet->http_url_name.ptr = &packet->payload[filename_start];
      packet->http_url_name.len = packet->line[0].len - (filename_start + 9);

      packet->http_method.ptr = packet->line[0].ptr;
      packet->http_method.len = filename_start - 1;

      if ((packet->http_url_name.len > 7) && (!strncmp((const char*) packet->http_url_name.ptr, "http://", 7))) {
        NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP_PROXY Found.\n");
        ndpi_int_http_add_connection(flow, NDPI_RESULT_BASE_HTTP_PROXY);
        check_content_type_and_change_protocol(ndpi_struct, flow);
      }

      if (filename_start == 8 && (memcmp(packet->payload, "CONNECT ", 8) == 0)) /* nathan@getoffmalawn.com */ {
        NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP_CONNECT Found.\n");
        ndpi_int_http_add_connection(flow, NDPI_RESULT_BASE_HTTP_CONNECT);
        check_content_type_and_change_protocol(ndpi_struct, flow);
      }

      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP START Found, we will look for sub-protocols (content and host)...\n");

      check_content_type_and_change_protocol(ndpi_struct, flow);

      if (packet->host_line.ptr != NULL) {
        flow->http_detected = 1;
        NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP START Found, we will look further for the response...\n");
        flow->l4.tcp.http_stage = packet->packet_direction + 1; // packet_direction 0: stage 1, packet_direction 1: stage 2
        return;
      }
    }

    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: REQUEST NOT HTTP CONFORM\n");
    flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP] = 1;
    flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP_CONNECT] = 1;
    flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP_PROXY] = 1;

  } else if ((flow->l4.tcp.http_stage == 1) || (flow->l4.tcp.http_stage == 2)) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP stage %u: \n", flow->l4.tcp.http_stage);

    /* At first check, if this is for sure a response packet (in another direction. If not, if http is detected do nothing now and return,
     * otherwise check the second packet for the http request . */
    if ((flow->l4.tcp.http_stage - packet->packet_direction) == 1) {

      if (flow->http_detected)
        return;

      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, " SECOND PAYLOAD TRAFFIC FROM CLIENT, FIRST PACKET MIGHT HAVE BEEN HTTP...UNKNOWN TRAFFIC, HERE FOR HTTP again.. \n");

      ndpi_parse_packet_line_info(ndpi_struct, flow);
      
      if (packet->parsed_lines <= 1) {
	
        /* wait some packets in case request is split over more than 2 packets */
        if (flow->packet_counter < 5) {
          NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "line still not finished, search next packet\n");
          return;
        } else {
          /* stop parsing here */
          NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP: PACKET DOES NOT HAVE A LINE STRUCTURE\n");
	  flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP] = 1;
	  flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP_CONNECT] = 1;
	  flow->ndpi_excluded_base[NDPI_RESULT_BASE_HTTP_PROXY] = 1;
          return;
        }
      }
      
      // http://www.slideshare.net/DSPIP/rtsp-analysis-wireshark
      if (packet->line[0].len >= 9 && memcmp(&packet->line[0].ptr[packet->line[0].len - 9], " HTTP/1.", 8) == 0) {

        NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found HTTP.\n");
        ndpi_int_http_add_connection(flow, NDPI_RESULT_BASE_HTTP);
        check_content_type_and_change_protocol(ndpi_struct, flow);
        NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "HTTP START Found in 2. packet, we will look further for the response....\n");
        flow->http_detected = 1;
      }
      
      return;
    }

    /* This is a packet in another direction. Check if we find the proper response. */
    /* We have received a response for a previously identified partial HTTP request */

    if ((packet->parsed_lines == 1) && (packet->packet_direction == 1 /* server -> client */)) {
      /*
	In apache if you do "GET /\n\n" the response comes without any header so we can assume that
	this can be the case
      */
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found HTTP. (apache)\n");
      ndpi_int_http_add_connection(flow, NDPI_RESULT_BASE_HTTP);
      check_content_type_and_change_protocol(ndpi_struct, flow);
      return;
    }

    /* If we already detected the http request, we can add the connection and then check for the sub-protocol*/
    if (flow->http_detected)
      ndpi_int_http_add_connection(flow, NDPI_RESULT_BASE_HTTP);

    /* Parse packet line and we look for the subprotocols */
    ndpi_parse_packet_line_info(ndpi_struct, flow);
    check_content_type_and_change_protocol(ndpi_struct, flow);

    flow->l4.tcp.http_stage = 0;
    return;
  }
}

void ndpi_register_proto_http (struct ndpi_detection_module_struct *ndpi_mod) {

  /* 8080 and 3128 for NDPI_RESULT_BASE_HTTP_PROXY */
  int tcp_ports[5] = {80, 8080, 3128, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};
  
  ndpi_initialize_scanner_base (ndpi_mod, NDPI_RESULT_BASE_HTTP, "HTTP", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_http_tcp);
  ndpi_initialize_scanner_base (ndpi_mod, NDPI_RESULT_BASE_HTTP_CONNECT, "HTTP_Connect", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD, tcp_ports, udp_ports, NULL);
  ndpi_initialize_scanner_base (ndpi_mod, NDPI_RESULT_BASE_HTTP_PROXY, "HTTP_Proxy", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD, tcp_ports, udp_ports, NULL);
}
