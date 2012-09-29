/*
 * dropbox.c
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


#include "ndpi_utils.h"

#ifdef NTOP_PROTOCOL_DROPBOX
static void ntop_int_dropbox_add_connection(struct ndpi_detection_module_struct
					    *ndpi_struct, u8 due_to_correlation)
{
  ndpi_int_add_connection(ndpi_struct,
			    NTOP_PROTOCOL_DROPBOX,
			    due_to_correlation ? NDPI_CORRELATED_PROTOCOL : NDPI_REAL_PROTOCOL);
}


static void ntop_check_dropbox(struct ndpi_detection_module_struct *ndpi_struct)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  struct ndpi_flow_struct *flow = ndpi_struct->flow;
  const u8 *packet_payload = packet->payload;
  u32 payload_len = packet->payload_packet_len;

  if(ndpi_struct->packet.udp != NULL) {
    u16 dropbox_port = htons(17500);

    if((ndpi_struct->packet.udp->source == dropbox_port)
       && (ndpi_struct->packet.udp->dest == dropbox_port)) {
      if(payload_len > 2) {
	if(strncmp(packet->payload, "{\"", 2) == 0) {
	  NDPI_LOG(NTOP_PROTOCOL_DROPBOX, ndpi_struct, NDPI_LOG_DEBUG, "Found dropbox.\n");
	  ntop_int_dropbox_add_connection(ndpi_struct, 0);
	  return;
	}
      }
    }
  }
  
  NDPI_LOG(NTOP_PROTOCOL_DROPBOX, ndpi_struct, NDPI_LOG_DEBUG, "exclude dropbox.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NTOP_PROTOCOL_DROPBOX);
}

void ntop_search_dropbox(struct ndpi_detection_module_struct *ndpi_struct)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;

  NDPI_LOG(NTOP_PROTOCOL_DROPBOX, ndpi_struct, NDPI_LOG_DEBUG, "dropbox detection...\n");

  /* skip marked packets */
  if (packet->detected_protocol_stack[0] != NTOP_PROTOCOL_DROPBOX) {
    if (packet->tcp_retransmission == 0) {
      ntop_check_dropbox(ndpi_struct);
    }
  }
}

#endif
