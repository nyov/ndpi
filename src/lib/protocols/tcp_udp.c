/*
 * tcp_or_udp.c
 *
 * Copyright (C) 2011-13 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */


#include "ndpi_utils.h"


void ndpi_search_tcp_or_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  if(packet->iph /* IPv4 Only: we need to support packet->iphv6 at some point */) {
    if(packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {

      /*
	Citrix GotoMeeting (AS16815, AS21866)
	216.115.208.0/20
	216.219.112.0/20
      */

      /* printf("[SSL] %08X / %08X\n", ntohl(packet->iph->saddr) , ntohl(packet->iph->daddr)); */

      if(((ntohl(packet->iph->saddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0xD873D000 /* 216.115.208.0 */)
	 || ((ntohl(packet->iph->daddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0xD873D000 /* 216.115.208.0 */)

	 || ((ntohl(packet->iph->saddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0xD8DB7000 /* 216.219.112.0 */)
	 || ((ntohl(packet->iph->daddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0xD8DB7000 /* 216.219.112.0 */)
	 ) {
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_CITRIX_ONLINE, NDPI_REAL_PROTOCOL);
	return;
      }

      /*
	Webex
	66.114.160.0/20
      */
      if(((ntohl(packet->iph->saddr) & 0xFFFFF000 /* 255.255.240.0 */) == 0x4272A000 /* 66.114.160.0 */)
	 || ((ntohl(packet->iph->daddr) & 0xFFFFF000 /* 255.255.240.0 */) ==0x4272A000 /* 66.114.160.0 */)) {
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_WEBEX, NDPI_REAL_PROTOCOL);
	return;
      }

      /*
	Apple (FaceTime, iMessage,...)
	17.0.0.0/8
      */
      if(((ntohl(packet->iph->saddr) & 0xFF000000 /* 255.0.0.0 */) == 0x11000000 /* 17.0.0.0 */)
	 || ((ntohl(packet->iph->daddr) & 0xFF000000 /* 255.0.0.0 */) == 0x11000000 /* 17.0.0.0 */)) {
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_APPLE, NDPI_REAL_PROTOCOL);
	return;
      }
  
      /*
	Google
	173.194.0.0/16
      */
      if(((ntohl(packet->iph->saddr) & 0xFFFF0000 /* 255.255.0.0 */) == 0xADC20000 /* 66.114.160.0 */)
	 || ((ntohl(packet->iph->daddr) & 0xFFFF0000 /* 255.255.0.0 */) ==0xDC20000 /* 66.114.160.0 */)) {
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_GOOGLE, NDPI_REAL_PROTOCOL);
	return;
      }
    }
  }
}


