/*
 * skype.c
 * Copyright (C) 2011 by ntop.org
 * 
 * This module is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License.
 * If not, see <http://www.gnu.org/licenses/>.
 * 
 */


#include "ipq_utils.h"

#ifdef NTOP_PROTOCOL_SKYPE
static void ntop_int_skype_add_connection(struct ipoque_detection_module_struct
					    *ipoque_struct, u8 due_to_correlation)
{
  ipoque_int_add_connection(ipoque_struct,
			    NTOP_PROTOCOL_SKYPE,
			    due_to_correlation ? IPOQUE_CORRELATED_PROTOCOL : IPOQUE_REAL_PROTOCOL);
}


static void ntop_check_skype(struct ipoque_detection_module_struct *ipoque_struct)
{
  struct ipoque_packet_struct *packet = &ipoque_struct->packet;
  struct ipoque_flow_struct *flow = ipoque_struct->flow;
  const u8 *packet_payload = packet->payload;
  u32 payload_len = packet->payload_packet_len;

  if(ipoque_struct->packet.udp != NULL) {
    if(payload_len >= 16) {
      /* skype-to-skype */
      if(packet->payload[2] == 0x02) {
	IPQ_LOG(NTOP_PROTOCOL_SKYPE, ipoque_struct, IPQ_LOG_DEBUG, "Found skype.\n");
	ntop_int_skype_add_connection(ipoque_struct, 0);
	return;
      }
    }
  }
  
  IPQ_LOG(NTOP_PROTOCOL_SKYPE, ipoque_struct, IPQ_LOG_DEBUG, "exclude skype.\n");
  IPOQUE_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NTOP_PROTOCOL_SKYPE);
}

void ntop_search_skype(struct ipoque_detection_module_struct *ipoque_struct)
{
  struct ipoque_packet_struct *packet = &ipoque_struct->packet;

  IPQ_LOG(NTOP_PROTOCOL_SKYPE, ipoque_struct, IPQ_LOG_DEBUG, "skype detection...\n");

  /* skip marked packets */
  if (packet->detected_protocol_stack[0] != NTOP_PROTOCOL_SKYPE) {
    if (packet->tcp_retransmission == 0) {
      ntop_check_skype(ipoque_struct);
    }
  }
}

#endif
