/*
 * ndpi_main.h
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


#ifndef __NDPI_MAIN_INCLUDE_FILE__
#define __NDPI_MAIN_INCLUDE_FILE__

#ifndef HAVE_NTOP 
#define HAVE_NTOP 1
#endif

#ifndef OPENDPI_NETFILTER_MODULE
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#endif

#if !(defined(HAVE_NTOP) && defined(WIN32))
#if 1 && !defined __APPLE__ && !defined __FreeBSD__

#ifndef OPENDPI_NETFILTER_MODULE
#  include <endian.h>
#  include <byteswap.h>
#else
#  include <asm/byteorder.h>
#endif

#endif							/* not WIN32 && not APPLE) */
#endif /* ntop */

/* default includes */

#if defined(__APPLE__) || (defined(HAVE_NTOP) && defined(WIN32)) || defined(__FreeBSD__)
#ifndef WIN32
#include <sys/param.h>
#include <limits.h>
#endif

#if defined(__FreeBSD__)
#include <netinet/in.h>
#endif

#ifdef NDPI_BUILD
#include "linux_compat.h"
#endif

#else							/* APPLE */
#ifndef OPENDPI_NETFILTER_MODULE
#  include <netinet/in.h>
#endif

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#endif

//#include <arpa/inet.h>


#define NDPI_USE_ASYMMETRIC_DETECTION             0
#define NDPI_SELECTION_BITMASK_PROTOCOL_SIZE			u_int32_t

#define NDPI_SELECTION_BITMASK_PROTOCOL_IP			(1<<0)
#define NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP			(1<<1)
#define NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP			(1<<2)
#define NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP		(1<<3)
#define NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD		(1<<4)
#define NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION	(1<<5)
#define NDPI_SELECTION_BITMASK_PROTOCOL_IPV6			(1<<6)
#define NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6		(1<<7)
#define NDPI_SELECTION_BITMASK_PROTOCOL_COMPLETE_TRAFFIC	(1<<8)
/* now combined detections */

/* v4 */
#define NDPI_SELECTION_BITMASK_PROTOCOL_TCP (NDPI_SELECTION_BITMASK_PROTOCOL_IP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP)
#define NDPI_SELECTION_BITMASK_PROTOCOL_UDP (NDPI_SELECTION_BITMASK_PROTOCOL_IP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP)
#define NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP (NDPI_SELECTION_BITMASK_PROTOCOL_IP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP)

/* v6 */
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP (NDPI_SELECTION_BITMASK_PROTOCOL_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_UDP (NDPI_SELECTION_BITMASK_PROTOCOL_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP (NDPI_SELECTION_BITMASK_PROTOCOL_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP)

/* v4 or v6 */
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP (NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP (NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP (NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP)


#define NDPI_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD		(NDPI_SELECTION_BITMASK_PROTOCOL_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_WITH_PAYLOAD		(NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD		(NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

/* does it make sense to talk about udp with payload ??? have you ever seen empty udp packets ? */
#define NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD		(NDPI_SELECTION_BITMASK_PROTOCOL_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_UDP_WITH_PAYLOAD		(NDPI_SELECTION_BITMASK_PROTOCOL_V6_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD		(NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

#define NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD		(NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP_WITH_PAYLOAD		(NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD		(NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

#define NDPI_SELECTION_BITMASK_PROTOCOL_TCP_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)

#define NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION)

#define NDPI_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

#define NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V6_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)
#define NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION	(NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION | NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD)

/* safe src/dst protocol check macros... */

#define NDPI_SRC_HAS_PROTOCOL(src,protocol) ((src) != NULL && NDPI_COMPARE_PROTOCOL_TO_BITMASK((src)->detected_protocol_bitmask,(protocol)) != 0)

#define NDPI_DST_HAS_PROTOCOL(dst,protocol) ((dst) != NULL && NDPI_COMPARE_PROTOCOL_TO_BITMASK((dst)->detected_protocol_bitmask,(protocol)) != 0)

#define NDPI_SRC_OR_DST_HAS_PROTOCOL(src,dst,protocol) (NDPI_SRC_HAS_PROTOCOL(src,protocol) || NDPI_SRC_HAS_PROTOCOL(dst,protocol))

/**
 * convenience macro to check for excluded protocol
 * a protocol is excluded if the flow is known and either the protocol is not detected at all
 * or the excluded bitmask contains the protocol
 */
#define NDPI_FLOW_PROTOCOL_EXCLUDED(ndpi_struct,flow,protocol) ((flow) != NULL && \
								( NDPI_COMPARE_PROTOCOL_TO_BITMASK((ndpi_struct)->detection_bitmask, (protocol)) == 0 || \
								  NDPI_COMPARE_PROTOCOL_TO_BITMASK((flow)->excluded_protocol_bitmask, (protocol)) != 0 ) )

/* misc definitions */
#define NDPI_DEFAULT_MAX_TCP_RETRANSMISSION_WINDOW_SIZE 0x10000


/* TODO: rebuild all memory areas to have a more aligned memory block here */

/* DEFINITION OF MAX LINE NUMBERS FOR line parse algorithm */
#define NDPI_MAX_PARSE_LINES_PER_PACKET                        200


/**********************
 * detection features *
 **********************/
#define NDPI_SELECT_DETECTION_WITH_REAL_PROTOCOL ( 1 << 0 )

#define NDPI_DIRECTCONNECT_CONNECTION_IP_TICK_TIMEOUT          600
#define NDPI_GADGADU_PEER_CONNECTION_TIMEOUT        	       120
#define NDPI_EDONKEY_UPPER_PORTS_ONLY                          0
#define NDPI_FTP_CONNECTION_TIMEOUT                            10
#define NDPI_PPLIVE_CONNECTION_TIMEOUT                         120
#define NDPI_IRC_CONNECTION_TIMEOUT                            120
#define NDPI_GNUTELLA_CONNECTION_TIMEOUT                       60
#define NDPI_BATTLEFIELD_CONNECTION_TIMEOUT                    60
#define NDPI_THUNDER_CONNECTION_TIMEOUT                        30
#define NDPI_RTSP_CONNECTION_TIMEOUT                           5
#define NDPI_TVANTS_CONNECTION_TIMEOUT                         5
#define NDPI_YAHOO_DETECT_HTTP_CONNECTIONS                     1
#define NDPI_YAHOO_LAN_VIDEO_TIMEOUT                           30
#define NDPI_ZATTOO_CONNECTION_TIMEOUT                         120
#define NDPI_ZATTOO_FLASH_TIMEOUT                              5
#define NDPI_JABBER_STUN_TIMEOUT                               30
#define NDPI_JABBER_FT_TIMEOUT				       5
#define NDPI_SOULSEEK_CONNECTION_IP_TICK_TIMEOUT               600
#define NDPI_MANOLITO_SUBSCRIBER_TIMEOUT                       120

#ifdef NDPI_ENABLE_DEBUG_MESSAGES

#define NDPI_LOG_BITTORRENT(proto, mod, log_level, args...)	\
  NDPI_LOG(proto,mod,log_level,args)

#define NDPI_LOG_GNUTELLA(proto, mod, log_level, args...)	\
  NDPI_LOG(proto,mod,log_level,args)

#define NDPI_LOG_EDONKEY(proto, mod, log_level, args...)	\
  NDPI_LOG(proto,mod,log_level,args)
#define NDPI_LOG(proto, mod, log_level, args...)		\
  {								\
    if(mod != NULL) {						\
      mod->ndpi_debug_print_file=__FILE__;                      \
      mod->ndpi_debug_print_function=__FUNCTION__;              \
      mod->ndpi_debug_print_line=__LINE__;                      \
      mod->ndpi_debug_printf(proto, mod, log_level, args);      \
    }								\
  }
#else							/* NDPI_ENABLE_DEBUG_MESSAGES */

#if defined(HAVE_NTOP) && defined(WIN32)
#define NDPI_LOG_BITTORRENT(...) {}
#define NDPI_LOG_GNUTELLA(...) {}
#define NDPI_LOG_EDONKEY(...) {}
#define NDPI_LOG(...) {}
#else
#define NDPI_LOG_BITTORRENT(proto, mod, log_level, args...) {}
#define NDPI_LOG_GNUTELLA(proto, mod, log_level, args...) {}
#define NDPI_LOG_EDONKEY(proto, mod, log_level, args...) {}
#define NDPI_LOG(proto, mod, log_level, args...) {}
#endif

#endif							/* NDPI_ENABLE_DEBUG_MESSAGES */

#include "ndpi_macros.h"
#include "ndpi_protocols_osdpi.h"

typedef struct ndpi_int_one_line_struct {
  const u_int8_t *ptr;
  u_int16_t len;
} ndpi_int_one_line_struct_t;

typedef struct ndpi_packet_struct {
  const struct iphdr *iph;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  const struct ndpi_ipv6hdr *iphv6;
#endif
  const struct tcphdr *tcp;
  const struct udphdr *udp;
  const u_int8_t *generic_l4_ptr;	/* is set only for non tcp-udp traffic */
  const u_int8_t *payload;

  u_int32_t tick_timestamp;

  u_int16_t detected_protocol_stack[NDPI_PROTOCOL_HISTORY_SIZE];
  u_int8_t detected_subprotocol_stack[NDPI_PROTOCOL_HISTORY_SIZE];

  /* this is for simple read-only access to the real protocol 
   * used for the main loop */
  u_int16_t real_protocol_read_only;

#if NDPI_PROTOCOL_HISTORY_SIZE > 1
#  if NDPI_PROTOCOL_HISTORY_SIZE > 5
#    error protocol stack size not supported
#  endif

  struct {
    u_int8_t entry_is_real_protocol:5;
    u_int8_t current_stack_size_minus_one:3;
  } 
#if !(defined(HAVE_NTOP) && defined(WIN32))
    __attribute__ ((__packed__))
#endif
    protocol_stack_info;
#endif

  struct ndpi_int_one_line_struct line[NDPI_MAX_PARSE_LINES_PER_PACKET];
  struct ndpi_int_one_line_struct
  unix_line[NDPI_MAX_PARSE_LINES_PER_PACKET];
  struct ndpi_int_one_line_struct host_line;
  struct ndpi_int_one_line_struct referer_line;
  struct ndpi_int_one_line_struct content_line;
  struct ndpi_int_one_line_struct accept_line;
  struct ndpi_int_one_line_struct user_agent_line;
  struct ndpi_int_one_line_struct http_url_name;
  struct ndpi_int_one_line_struct http_encoding;
  struct ndpi_int_one_line_struct http_transfer_encoding;
  struct ndpi_int_one_line_struct http_contentlen;
  struct ndpi_int_one_line_struct http_cookie;
  struct ndpi_int_one_line_struct http_x_session_type;
  struct ndpi_int_one_line_struct server_line;
  struct ndpi_int_one_line_struct http_method;
  struct ndpi_int_one_line_struct http_response;


  u_int16_t l3_packet_len;
  u_int16_t l4_packet_len;
  u_int16_t payload_packet_len;
  u_int16_t actual_payload_len;
  u_int16_t num_retried_bytes;
  u_int16_t parsed_lines;
  u_int16_t parsed_unix_lines;
  u_int16_t empty_line_position;
  u_int8_t tcp_retransmission;
  u_int8_t l4_protocol;

  u_int8_t packet_lines_parsed_complete;
  u_int8_t packet_unix_lines_parsed_complete;
  u_int8_t empty_line_position_set;
  u_int8_t packet_direction:1;
} ndpi_packet_struct_t;

struct ndpi_detection_module_struct;
struct ndpi_flow_struct;

typedef struct ndpi_call_function_struct {
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_bitmask;
  void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);
  u_int8_t detection_feature;
} ndpi_call_function_struct_t;

typedef struct ndpi_detection_module_struct {
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  NDPI_PROTOCOL_BITMASK generic_http_packet_bitmask;
  
  u_int32_t current_ts;
  u_int32_t ticks_per_second;

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  void *user_data;
#endif
  /* callback function buffer */
  struct ndpi_call_function_struct callback_buffer[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size;

  struct ndpi_call_function_struct callback_buffer_tcp_no_payload[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size_tcp_no_payload;

  struct ndpi_call_function_struct callback_buffer_tcp_payload[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size_tcp_payload;


  struct ndpi_call_function_struct callback_buffer_udp[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size_udp;


  struct ndpi_call_function_struct callback_buffer_non_tcp_udp[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
  u_int32_t callback_buffer_size_non_tcp_udp;

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  /* debug callback, only set when debug is used */
  ndpi_debug_function_ptr ndpi_debug_printf;
  const char *ndpi_debug_print_file;
  const char *ndpi_debug_print_function;
  u_int32_t ndpi_debug_print_line;
#endif
  /* misc parameters */
  u_int32_t tcp_max_retransmission_window_size;

  u_int32_t edonkey_upper_ports_only:1;
  u_int32_t edonkey_safe_mode:1;
  u_int32_t directconnect_connection_ip_tick_timeout;

  /*gadu gadu*/
  u_int32_t gadugadu_peer_connection_timeout;
  /* pplive params */
  u_int32_t pplive_connection_timeout;
  /* ftp parameters */
  u_int32_t ftp_connection_timeout;
  /* irc parameters */
  u_int32_t irc_timeout;
  /* gnutella parameters */
  u_int32_t gnutella_timeout;
  /* battlefield parameters */
  u_int32_t battlefield_timeout;
  /* thunder parameters */
  u_int32_t thunder_timeout;
  /* SoulSeek parameters */
  u_int32_t soulseek_connection_ip_tick_timeout;
  /* rtsp parameters */
  u_int32_t rtsp_connection_timeout;
  /* tvants parameters */
  u_int32_t tvants_connection_timeout;
  u_int32_t orb_rstp_ts_timeout;
  /* yahoo */
  //      u_int32_t yahoo_http_filetransfer_timeout;
  u_int8_t yahoo_detect_http_connections;
  u_int32_t yahoo_lan_video_timeout;
  u_int32_t zattoo_connection_timeout;
  u_int32_t jabber_stun_timeout;
  u_int32_t jabber_file_transfer_timeout;
  u_int32_t manolito_subscriber_timeout;
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
#define NDPI_IP_STRING_SIZE 40
  char ip_string[NDPI_IP_STRING_SIZE];
#endif
  u_int8_t ip_version_limit;
} ndpi_detection_module_struct_t;

u_int32_t ndpi_bytestream_to_number(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);

/* NTOP */
#if !(defined(HAVE_NTOP) && defined(WIN32))
static inline
#else
__forceinline static
#endif
u_int16_t ntohs_ndpi_bytestream_to_number(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read)
{
  u_int16_t val = ndpi_bytestream_to_number(str, max_chars_to_read, bytes_read);
  return ntohs(val);
}

u_int64_t ndpi_bytestream_to_number64(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);

u_int32_t ndpi_bytestream_dec_or_hex_to_number(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);
u_int64_t ndpi_bytestream_dec_or_hex_to_number64(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);

u_int32_t ndpi_bytestream_to_ipv4(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read);

#ifdef NDPI_DETECTION_SUPPORT_IPV6
struct ndpi_ip6_addr {
  union {
    u_int8_t u6_addr8[16];
    u_int16_t u6_addr16[8];
    u_int32_t u6_addr32[4];
    u_int64_t u6_addr64[2];
  } ndpi_v6_u;

#define ndpi_v6_addr			ndpi_v6_u.u6_addr8
#define ndpi_v6_addr16		ndpi_v6_u.u6_addr16
#define ndpi_v6_addr32		ndpi_v6_u.u6_addr32
#define ndpi_v6_addr64		ndpi_v6_u.u6_addr64
};

struct ndpi_ipv6hdr {
  /* use userspace and kernelspace compatible compile parameters */
#if defined(__LITTLE_ENDIAN_BITFIELD) || (defined( __LITTLE_ENDIAN) && __BYTE_ORDER == __LITTLE_ENDIAN) || defined(__LITTLE_ENDIAN__)
  u_int8_t priority:4, version:4;
#elif defined(__BIG_ENDIAN_BITFIELD) || (defined( __BIG_ENDIAN) && __BYTE_ORDER == __BIG_ENDIAN)
  u_int8_t version:4, priority:4;
#else
#error	"__LITTLE_ENDIAN_BITFIELD or __BIG_ENDIAN_BITFIELD must be defined, should be done by <asm/byteorder.h>"
#endif

  u_int8_t flow_lbl[3];

  u_int16_t payload_len;
  u_int8_t nexthdr;
  u_int8_t hop_limit;

  struct ndpi_ip6_addr saddr;
  struct ndpi_ip6_addr daddr;
};
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

typedef union {
  u_int32_t ipv4;
  u_int8_t ipv4_u_int8_t[4];
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  struct ndpi_ip6_addr ipv6;
#endif
} ndpi_ip_addr_t;


#include "ndpi_api.h"
#include "ndpi_protocol_history.h"
#include "ndpi_structs.h"

/* function to parse a packet which has line based information into a line based structure
 * this function will also set some well known line pointers like:
 *  - host, user agent, empty line,....
 */
extern void ndpi_parse_packet_line_info(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
extern void ndpi_parse_packet_line_info_unix(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
extern u_int16_t ndpi_check_for_email_address(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, u_int16_t counter);
extern void ndpi_int_change_packet_protocol(struct ndpi_detection_module_struct *ndpi_struct,
					    struct ndpi_flow_struct *flow,
					    u_int16_t detected_protocol, ndpi_protocol_type_t protocol_type);
extern void ndpi_int_change_protocol(struct ndpi_detection_module_struct *ndpi_struct,
				     struct ndpi_flow_struct *flow,
				     u_int16_t detected_protocol,
				     ndpi_protocol_type_t protocol_type);
extern void ndpi_int_reset_packet_protocol(struct ndpi_packet_struct *packet);
extern void ndpi_int_reset_protocol(struct ndpi_flow_struct *flow);
extern void ndpi_ip_clear(ndpi_ip_addr_t * ip);
extern int ndpi_ip_is_set(const ndpi_ip_addr_t * ip);
extern int ndpi_packet_src_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t * ip);
extern int ndpi_packet_dst_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t * ip);
extern void ndpi_packet_src_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t * ip);
extern void ndpi_packet_dst_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t * ip);
extern char *ndpi_get_ip_string(struct ndpi_detection_module_struct *ndpi_struct, const ndpi_ip_addr_t * ip);
extern char *ndpi_get_packet_src_ip_string(struct ndpi_detection_module_struct *ndpi_struct,
					   const struct ndpi_packet_struct *packet);

#endif							/* __NDPI_MAIN_INCLUDE_FILE__ */
