/*
 * ndpi_protocol_history.h
 * Copyright (C) 2009-2011 by ipoque GmbH
 * 
 * This file is part of OpenDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * OpenDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * OpenDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with OpenDPI.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */



#ifndef NDPI_PROTOCOL_HISTORY_H
#define NDPI_PROTOCOL_HISTORY_H

typedef enum {
	NDPI_REAL_PROTOCOL = 0,
	NDPI_CORRELATED_PROTOCOL = 1
} ndpi_protocol_type_t;

/* generic function for setting a protocol for a flow
 *
 * what it does is:
 * 1.call ndpi_int_change_protocol
 * 2.set protocol in detected bitmask for src and dst
 */
void ndpi_int_add_connection(struct ndpi_detection_module_struct *ndpi_struct,
							   u16 detected_protocol, ndpi_protocol_type_t protocol_type);

/* generic function for changing the flow protocol
 *
 * what it does is:
 * 1.update the flow protocol stack with the new protocol
 */
void ndpi_int_change_flow_protocol(struct ndpi_detection_module_struct *ndpi_struct,
									 u16 detected_protocol, ndpi_protocol_type_t protocol_type);

/* generic function for changing the packetprotocol
 *
 * what it does is:
 * 1.update the packet protocol stack with the new protocol
 */
void ndpi_int_change_packet_protocol(struct ndpi_detection_module_struct *ndpi_struct,
									   u16 detected_protocol, ndpi_protocol_type_t protocol_type);

/* generic function for changing the protocol
 *
 * what it does is:
 * 1.update the flow protocol stack with the new protocol
 * 2.update the packet protocol stack with the new protocol
 */
#if !(defined(HAVE_NTOP) && defined(WIN32))
static inline
#else
__forceinline static
#endif
	void ndpi_int_change_protocol(struct ndpi_detection_module_struct
																	  *ndpi_struct, u16 detected_protocol,
																	  ndpi_protocol_type_t protocol_type)
{
	ndpi_int_change_flow_protocol(ndpi_struct, detected_protocol, protocol_type);
	ndpi_int_change_packet_protocol(ndpi_struct, detected_protocol, protocol_type);
}


/* turns a packet back to unknown */
#if !(defined(HAVE_NTOP) && defined(WIN32))
static inline
#else
__forceinline static
#endif
	 void ndpi_int_reset_packet_protocol(struct ndpi_detection_module_struct
																			*ndpi_struct)
{
	struct ndpi_packet_struct *packet = &ndpi_struct->packet;

	packet->detected_protocol_stack[0] = NDPI_PROTOCOL_UNKNOWN;

#if NDPI_PROTOCOL_HISTORY_SIZE > 1
	packet->protocol_stack_info.current_stack_size_minus_one = 0;
	packet->protocol_stack_info.entry_is_real_protocol = 0;
#endif
}

/* turns a flow back to unknown */
#if !(defined(HAVE_NTOP) && defined(WIN32))
static inline
#else
__forceinline static
#endif
	 void ndpi_int_reset_protocol(struct ndpi_detection_module_struct
																	 *ndpi_struct)
{
	struct ndpi_flow_struct *flow = ndpi_struct->flow;

	if (flow) {
		flow->detected_protocol_stack[0] = NDPI_PROTOCOL_UNKNOWN;

#if NDPI_PROTOCOL_HISTORY_SIZE > 1
		flow->protocol_stack_info.current_stack_size_minus_one = 0;
		flow->protocol_stack_info.entry_is_real_protocol = 0;
#endif
	}

	ndpi_int_reset_packet_protocol(ndpi_struct);
}

#endif
