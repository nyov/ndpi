/*
 * ndpi_public_functions.h
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


#ifndef __NDPI_API_INCLUDE_FILE__
#error CANNOT INCLUDE THIS .H FILE, INCLUDE NDPI_API.H
#endif

#ifndef __NDPI_PUBLIC_FUNCTIONS_H__
#define __NDPI_PUBLIC_FUNCTIONS_H__

//#include "ndpi_structs.h"

#ifdef __cplusplus
extern "C" {
#endif
  /* Forward */
  struct ndpi_flow_struct;
  struct ndpi_id_struct;

  /**
   * struct for a unique ipv4 flow address
   */
  typedef struct ndpi_unique_flow_ipv4_address_struct {
    /**
     * lower ip
     */
    u_int32_t lower_ip;
    /**
     * upper ip
     */
    u_int32_t upper_ip;
    /* we need 3 dummies to fill up to ipv6 address size */
    /**
     * this is only needed to become the same size like a unique ipv6 struct
     */
    u_int64_t dummy[3];
  } ndpi_unique_flow_ipv4_address_struct_t;

  /**
   * struct for a unique ipv6 flow address
   */
  typedef struct ndpi_unique_flow_ipv6_address_struct {
    /**
     * lower ip
     */
    u_int64_t lower_ip[2];
    /**
     * upper ip
     */
    u_int64_t upper_ip[2];
  } ndpi_unique_flow_ipv6_address_struct_t;

  /**
   * struct for a unique ipv4 and ipv6 5-tuple (ip,ip,port,port,protocol)
   */
  typedef struct ndpi_unique_flow_ipv4_and_6_struct {
    /* only ip addresses are different, to minimize compare operations for hash tables, store ipv4 or ipv6 always in the first bit */
    /**
     * saves if it is a ipv6, if it false so it is a ipv4
     */
    u_int16_t is_ip_v6;
    /**
     * the protocol, 16 bit wide for alignemt reasons
     */
    u_int16_t protocol;			/* for alignment reason, protocol is 16 bit, not 8 bit */
    /**
     * the port of the lower ip address
     */
    u_int16_t lower_port;
    /**
     * the port of the upper ip address
     */
    u_int16_t upper_port;
    union {
      /**
       * the ipv4 flow address struct. use the same memory area like ipv6 (union)
       */
      struct ndpi_unique_flow_ipv4_address_struct ipv4;
      /**
       * the ipv6 flow address struct. use the same memory area like ipv4 (union)
       */
      struct ndpi_unique_flow_ipv6_address_struct ipv6;
    } ip;
  } ndpi_unique_flow_ipv4_and_6_struct_t;

  typedef enum {

    NDPI_LOG_ERROR,
    NDPI_LOG_TRACE,
    NDPI_LOG_DEBUG
  } ndpi_log_level_t;

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


  /* Public malloc/free */
  void* ndpi_malloc(unsigned long size);
  void* ndpi_calloc(unsigned long count, unsigned long size);
  void  ndpi_free(void *ptr);
  void *ndpi_realloc(void *ptr, size_t old_size, size_t new_size);
  char *ndpi_strdup(const char *s);
 /*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
  char* ndpi_strnstr(const char *s, const char *find, size_t slen);

  /**
   * This function returns a new initialized detection module. 
   * @param ticks_per_second the timestamp resolution per second (like 1000 for millisecond resolution)
   * @param ndpi_malloc function pointer to a memory allocator
   * @param ndpi_debug_printf a function pointer to a debug output function, use NULL in productive envionments
   * @return the initialized detection module
   */
  struct ndpi_detection_module_struct *ndpi_init_detection_module(u_int32_t ticks_per_second,
								  void* (*__ndpi_malloc)(unsigned long size),
								  void  (*__ndpi_free)(void *ptr),
								  ndpi_debug_function_ptr ndpi_debug_printf);

  /**
   * This function destroys the detection module
   * @param ndpi_struct the to clearing detection module
   * @param ndpi_free function pointer to a memory free function
   */
  void ndpi_exit_detection_module(struct ndpi_detection_module_struct *ndpi_struct, void (*ndpi_free) (void *ptr));
  
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
  void ndpi_detection_process_packet(struct ndpi_detection_module_struct *ndpi_struct,
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
  /**
   * build the unique key of a flow
   *
   * @param l3 pointer to the layer 3 data
   * @param l3_len length of the layer 3 data
   * @param l4 pointer to the layer 4 data
   * @param l4_len length of the layer 4 data
   * @param l4_protocol layer 4 protocol
   * @param key_return filled with the unique key if return value == 0, undefined otherwise
   * @param dir_return filled with a direction flag (0 or 1), can be NULL
   * @param flags limit operation on ipv4 or ipv6 packets, possible values are NDPI_DETECTION_ONLY_IPV4 or NDPI_DETECTION_ONLY_IPV6; 0 means any
   * @return 0 if key could be built, != 0 otherwise
   */
  u_int8_t ndpi_detection_build_key(const u_int8_t * l3, u_int16_t l3_len, const u_int8_t * l4, u_int16_t l4_len, u_int8_t l4_protocol,
				    struct ndpi_unique_flow_ipv4_and_6_struct *key_return, u_int8_t * dir_return, u_int32_t flags);

  char* ndpi_revision(void);
   
   char *ndpi_get_result_ip (struct ndpi_detection_module_struct *ndpi_mod, ndpi_result_ip_t id);
   char *ndpi_get_result_base (struct ndpi_detection_module_struct *ndpi_mod, ndpi_result_base_t id);
   char *ndpi_get_result_app (struct ndpi_detection_module_struct *ndpi_mod, ndpi_result_app_t id);
   char *ndpi_get_result_content (struct ndpi_detection_module_struct *ndpi_mod, ndpi_result_content_t id);
   char *ndpi_get_result_service (struct ndpi_detection_module_struct *ndpi_mod, ndpi_result_service_t id);

#ifdef __cplusplus
}
#endif
#endif
