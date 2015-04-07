/*
 * proto_netflow.c
 *
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

#ifndef __KERNEL__
#ifdef WIN32
extern int gettimeofday(struct timeval * tp, struct timezone * tzp);
#endif
#define do_gettimeofday(a) gettimeofday(a, NULL)
#endif

void ndpi_search_netflow(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "netflow detection...\n");
  
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t payload_len = packet->payload_packet_len;
  time_t now;
  struct timeval now_tv;
  
    /* Break after 20 packets. */
  if (flow->packet_counter > 20) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Exclude netflow.\n");
    flow->ndpi_excluded_app[NDPI_RESULT_APP_NETFLOW] = 1;
    return;
  }

  if((packet->udp != NULL) && (payload_len >= 24)) {
    u_int16_t version = (packet->payload[0] << 8) + packet->payload[1], uptime_offset;
    u_int32_t when, *_when;
    u_int16_t n = (packet->payload[2] << 8) + packet->payload[3];

    switch(version) {
    case 1:
    case 5:
    case 7:
    case 9:
      {      
	u_int16_t num_flows = n;

	if((num_flows == 0) || (num_flows > 30))
	  return;
      }
      uptime_offset = 8;
      break;
    case 10: /* IPFIX */
      {      
	u_int16_t ipfix_len = n;

	if(ipfix_len != payload_len)
	  return;
      }    
      uptime_offset = 4;
      break;
    default:
      return;
    }

    _when = (u_int32_t*)&packet->payload[uptime_offset]; /* Sysuptime */
    when = ntohl(*_when);

    do_gettimeofday(&now_tv);
    now = now_tv.tv_sec;

    if(((version == 1) && (when == 0))
       || ((when >= 946684800 /* 1/1/2000 */) && (when <= now))) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Found netflow.\n");
      flow->ndpi_result_app = NDPI_RESULT_APP_NETFLOW;
      flow->ndpi_excluded_app[NDPI_RESULT_APP_NETFLOW] = 1;
      return;
    }
  }
}

void ndpi_register_proto_netflow (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {2055, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_NETFLOW, "NetFlow", NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_netflow);
}
