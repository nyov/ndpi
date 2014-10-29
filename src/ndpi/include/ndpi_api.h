/*
 * ndpi_api.h
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


#ifndef __NDPI_API_H__
#define __NDPI_API_H__

#include "ndpi_main.h"

#ifdef __cplusplus
extern "C" {
#endif

  typedef void (*ndpi_debug_function_ptr) (u_int32_t protocol, void *module_struct, ndpi_log_level_t log_level, const char *format, ...);

  /**
   * This function returns the size of the flow struct
   * @return the size of the flow struct
   */
  u_int32_t ndpi_detection_get_sizeof_ndpi_flow_struct(void);

  /**
   * This function returns the size of the id struct
   * @return the size of the id struct
   */
  u_int32_t ndpi_detection_get_sizeof_ndpi_id_struct(void);


  /* Public memory functions. */
  void* ndpi_calloc(unsigned long count, unsigned long size);
  void *ndpi_realloc(void *ptr, size_t old_size, size_t new_size);
  char *ndpi_strdup(const char *s);
  
  struct ndpi_flow_struct *create_ndpi_flow_struct_pointer(void);
  void clear_ndpi_flow_struct_pointer(struct ndpi_flow_struct *ndpi_flow_struct_pointer);
  void delete_ndpi_flow_struct_pointer(struct ndpi_flow_struct *ndpi_flow_struct_pointer);
  
 /*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
  char* ndpi_strnstr(const char *s, const char *find, size_t slen);

  /**
   * This function returns a new initialized detection module. 
   * @param ticks_per_second the timestamp resolution per second (like 1000 for millisecond resolution)
   * @param ndpi_debug_printf a function pointer to a debug output function, use NULL in productive envionments
   * @return the initialized detection module
   */
  struct ndpi_detection_module_struct *create_ndpi_detection_module_struct_pointer(u_int32_t ticks_per_second, ndpi_debug_function_ptr ndpi_debug_printf);

  /**
   * This function destroys the detection module
   * @param ndpi_struct the to clearing detection module
   */
  void delete_ndpi_detection_module_struct_pointer(struct ndpi_detection_module_struct *ndpi_struct);
  
  /**
   * This function will processes one packet and returns the ID of the detected protocol.
   * This is the main packet processing function. 
   *
   * @param ndpi_struct the detection module
   * @param flow void pointer to the connection state machine
   * @param packet the packet as unsigned char pointer with the length of packetlen. the pointer must point to the Layer 3 (IP header)
   * @param packetlen the length of the packet
   * @param current_tick the current timestamp for the packet
   * @param src void pointer to the source subscriber state machine
   * @param dst void pointer to the destination subscriber state machine
   */
  void ndpi_process_ip_packet(struct ndpi_detection_module_struct *ndpi_struct,
				struct ndpi_flow_struct *flow,
				const unsigned char *packet,
				const unsigned short packetlen,
				const u_int32_t current_tick, 
				struct ndpi_id_struct *src, 
				struct ndpi_id_struct *dst
 			      );

#define NDPI_DETECTION_ONLY_IPV4 ( 1 << 0 )
#define NDPI_DETECTION_ONLY_IPV6 ( 1 << 1 )

  /**
   * query the pointer to the layer 4 packet
   *
   * @param l3 pointer to the layer 3 data
   * @param l3_len length of the layer 3 data
   * @param l4_return filled with the pointer the layer 4 data if return value == 0, undefined otherwise
   * @param l4_len_return filled with the length of the layer 4 data if return value == 0, undefined otherwise
   * @param l4_protocol_return filled with the protocol of the layer 4 data if return value == 0, undefined otherwise
   * @param flags limit operation on ipv4 or ipv6 packets, possible values are NDPI_DETECTION_ONLY_IPV4 or NDPI_DETECTION_ONLY_IPV6; 0 means any
   * @return 0 if correct layer 4 data could be found, != 0 otherwise
   */
  u_int8_t ndpi_detection_get_l4(const u_int8_t * l3, u_int16_t l3_len, const u_int8_t ** l4_return, u_int16_t * l4_len_return,
				 u_int8_t * l4_protocol_return, u_int32_t flags);

  char* ndpi_revision(void);
   
   ndpi_result_ip_t ndpi_get_result_ip_id (struct ndpi_flow_struct *ndpi_flow_struct_pointer);
   ndpi_result_base_t ndpi_get_result_base_id (struct ndpi_flow_struct *ndpi_flow_struct_pointer);
   ndpi_result_app_t ndpi_get_result_app_id (struct ndpi_flow_struct *ndpi_flow_struct_pointer);
   ndpi_result_content_t ndpi_get_result_content_id (struct ndpi_flow_struct *ndpi_flow_struct_pointer);
   ndpi_result_service_t ndpi_get_result_service_id (struct ndpi_flow_struct *ndpi_flow_struct_pointer);
   ndpi_result_cdn_t ndpi_get_result_cdn_id (struct ndpi_flow_struct *ndpi_flow_struct_pointer);
   
   char *ndpi_get_result_ip_name (struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *ndpi_flow_struct_pointer);
   char *ndpi_get_result_base_name (struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *ndpi_flow_struct_pointer);
   char *ndpi_get_result_app_name (struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *ndpi_flow_struct_pointer);
   char *ndpi_get_result_content_name (struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *ndpi_flow_struct_pointer);
   char *ndpi_get_result_service_name (struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *ndpi_flow_struct_pointer);
   char *ndpi_get_result_cdn_name (struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *ndpi_flow_struct_pointer);

#ifdef __cplusplus
}
#endif
#endif
