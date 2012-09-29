/*
 * dcerpc.c
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

#ifdef NTOP_PROTOCOL_DCERPC

static void ntop_int_dcerpc_add_connection(struct ndpi_detection_module_struct
					     *ndpi_struct)
{
  ndpi_int_add_connection(ndpi_struct, NTOP_PROTOCOL_DCERPC, NDPI_REAL_PROTOCOL);
}

void ntop_search_dcerpc(struct ndpi_detection_module_struct *ndpi_struct)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  struct ndpi_flow_struct *flow = ndpi_struct->flow;

  if((packet->tcp != NULL) 
     && (packet->payload_packet_len > 64) 
     && ((ntohs(packet->tcp->source) == 135) || (ntohs(packet->tcp->dest) == 135))
     && (packet->payload[0] == 0x05) /* version 5 */
     && (packet->payload[2] < 16) /* Packet type */
     ) {	 
    NDPI_LOG(NDPI_PROTOCOL_DCERPC, ndpi_struct, NDPI_LOG_DEBUG, "DCERPC match\n");	  
    ntop_int_dcerpc_add_connection(ndpi_struct);
    return;
  }

  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NTOP_PROTOCOL_DCERPC);
}

#endif
