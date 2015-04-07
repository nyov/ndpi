/*
 * ndpi_typedefs.h
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
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

#ifndef __NDPI_TYPEDEFS_FILE__
#define __NDPI_TYPEDEFS_FILE__

#ifdef NDPI_DETECTION_SUPPORT_IPV6
struct ndpi_ip6_addr {
  union {
    u_int8_t u6_addr8[16];
    u_int16_t u6_addr16[8];
    u_int32_t u6_addr32[4];
    u_int64_t u6_addr64[2];
  } ndpi_v6_u;

#define ndpi_v6_addr		ndpi_v6_u.u6_addr8
#define ndpi_v6_addr16		ndpi_v6_u.u6_addr16
#define ndpi_v6_addr32		ndpi_v6_u.u6_addr32
#define ndpi_v6_addr64		ndpi_v6_u.u6_addr64
};

struct ndpi_ipv6hdr {
  /* use userspace and kernelspace compatible compile parameters */
#if defined(__LITTLE_ENDIAN__)
  u_int8_t priority:4, version:4;
#elif defined(__BIG_ENDIAN__)
  u_int8_t version:4, priority:4;
#else
# error "Byte order must be defined"
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

typedef struct ndpi_id_struct {
  ndpi_ip_addr_t rtsp_ip_address;
  u_int32_t yahoo_video_lan_timer;
  u_int32_t last_time_port_used[16];
  u_int32_t irc_ts;
  u_int32_t gnutella_ts;
  u_int32_t battlefield_ts;
  u_int32_t thunder_ts;
  u_int32_t rtsp_timer;
  u_int32_t oscar_last_safe_access_time;
  u_int32_t zattoo_ts;
  u_int32_t jabber_stun_or_ft_ts;
  u_int32_t directconnect_last_safe_access_time;
  u_int32_t soulseek_last_safe_access_time;
  u_int16_t detected_directconnect_port;
  u_int16_t detected_directconnect_udp_port;
  u_int16_t detected_directconnect_ssl_port;
  u_int16_t irc_port[16];
#define JABBER_MAX_STUN_PORTS 6
  u_int16_t jabber_voice_stun_port[JABBER_MAX_STUN_PORTS];
  u_int16_t jabber_file_transfer_port[2];
  u_int16_t detected_gnutella_udp_port1;
  u_int16_t detected_gnutella_udp_port2;
  u_int16_t soulseek_listen_port;
  u_int8_t irc_number_of_port;
  u_int8_t jabber_voice_stun_used_ports;
  u_int32_t yahoo_video_lan_dir:1;
  u_int32_t yahoo_conf_logged_in:1;
  u_int32_t yahoo_voice_conf_logged_in:1;
  u_int32_t rtsp_ts_set:1;
} ndpi_id_struct;

/* ************************************************** */ 

struct ndpi_flow_tcp_struct {
  u_int16_t smtp_command_bitmask;
  u_int16_t pop_command_bitmask;
  u_int16_t qq_nxt_len;
  u_int8_t tds_login_version;
  u_int8_t irc_stage;
  u_int8_t irc_port;
  u_int8_t gnutella_msg_id[3];
  u_int32_t irc_3a_counter:3;
  u_int32_t irc_stage2:5;
  u_int32_t irc_direction:2;
  u_int32_t irc_0x1000_full:1;
  u_int32_t winmx_stage:1;			// 0-1
  u_int32_t soulseek_stage:2;
  u_int32_t filetopia_stage:2;
  u_int32_t tds_stage:3;
  u_int32_t usenet_stage:2;
  u_int32_t imesh_stage:4;
  u_int32_t http_setup_dir:2;
  u_int32_t http_stage:2;
  u_int32_t http_empty_line_seen:1;
  u_int32_t http_wait_for_retransmission:1;
  u_int32_t gnutella_stage:2;		//0-2
  u_int32_t mms_stage:2;
  u_int32_t yahoo_sip_comm:1;
  u_int32_t yahoo_http_proxy_stage:2;
  u_int32_t msn_stage:3;
  u_int32_t msn_ssl_ft:2;
  u_int32_t ssh_stage:3;
  u_int32_t vnc_stage:2;			// 0 - 3
  u_int32_t telnet_stage:2;			// 0 - 2
  u_int8_t ssl_stage:2, ssl_seen_client_cert:1, ssl_seen_server_cert:1; // 0 - 5
  u_int32_t postgres_stage:3;
  u_int32_t ddlink_server_direction:1;
  u_int32_t seen_syn:1;
  u_int32_t seen_syn_ack:1;
  u_int32_t seen_ack:1;
  u_int32_t icecast_stage:1;
  u_int32_t dofus_stage:1;
  u_int32_t fiesta_stage:2;
  u_int32_t wow_stage:2;
  u_int32_t veoh_tv_stage:2;
  u_int32_t shoutcast_stage:2;
  u_int32_t rtp_special_packets_seen:1;
  u_int32_t mail_pop_stage:2;
  u_int32_t mail_imap_stage:3;
  u_int8_t skype_packet_id;
  u_int8_t citrix_packet_id;
  u_int8_t lotus_notes_packet_id;
  u_int8_t teamviewer_stage;
  u_int8_t prev_zmq_pkt_len;
  u_char prev_zmq_pkt[10];
}

/* ************************************************** */ 

#if !defined(WIN32)
  __attribute__ ((__packed__))
#endif
  ;

struct ndpi_flow_udp_struct {
  u_int32_t battlefield_msg_id;
  u_int32_t snmp_msg_id;
  u_int32_t battlefield_stage:3;
  u_int32_t snmp_stage:2;
  u_int32_t ppstream_stage:3;		// 0-7
  u_int32_t halflife2_stage:2;		// 0 - 2
  u_int32_t tftp_stage:1;
  u_int32_t aimini_stage:5;
  u_int32_t xbox_stage:1;
  u_int8_t skype_packet_id;
  u_int8_t teamviewer_stage;
}

/* ************************************************** */ 

#if !defined(WIN32)
  __attribute__ ((__packed__))
#endif
  ;

typedef struct ndpi_int_one_line_struct {
  const u_int8_t *ptr;
  u_int16_t len;
} ndpi_int_one_line_struct_t;

typedef struct ndpi_packet_struct {
  const struct ndpi_iphdr *iph;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  const struct ndpi_ipv6hdr *iphv6;
#endif
  const struct ndpi_tcphdr *tcp;
  const struct ndpi_udphdr *udp;
  const u_int8_t *generic_l4_ptr;	/* is set only for non tcp-udp traffic */
  const u_int8_t *payload;

  u_int32_t tick_timestamp;

  struct ndpi_int_one_line_struct line[NDPI_MAX_PARSE_LINES_PER_PACKET];
  struct ndpi_int_one_line_struct unix_line[NDPI_MAX_PARSE_LINES_PER_PACKET];
  struct ndpi_int_one_line_struct host_line;
  struct ndpi_int_one_line_struct forwarded_line;
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
  u_int8_t ssl_certificate_detected:4, ssl_certificate_num_checks:4;
  
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet;
  
} ndpi_packet_struct_t;

struct ndpi_detection_module_struct;
struct ndpi_flow_struct;

typedef struct _ndpi_automa {
  void *ac_automa; /* Real type is AC_AUTOMATA_t */
  u_int8_t ac_automa_finalized;
} ndpi_automa;

typedef struct ndpi_scanner_ip {
  ndpi_result_ip_t id;
  char *name;
  void (*func) (struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
} ndpi_scanner_ip_t;

typedef struct ndpi_scanner_base {
  ndpi_result_base_t id;
  char *name;
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet;
  int default_tcp_ports[5];
  int default_udp_ports[5];
  void (*func) (struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
} ndpi_scanner_base_t;

typedef struct ndpi_scanner_app {
  ndpi_result_app_t id;
  char *name;
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet;
  int default_tcp_ports[5];
  int default_udp_ports[5];
  void (*func) (struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
} ndpi_scanner_app_t;

typedef struct ndpi_scanner_content {
  ndpi_result_content_t id;
  char *name;
  void (*func) (struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
} ndpi_scanner_content_t;

typedef struct ndpi_scanner_service {
  ndpi_result_service_t id;
  char *name;
  void (*func) (struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
} ndpi_scanner_service_t;

typedef struct ndpi_scanner_cdn {
  ndpi_result_cdn_t id;
  char *name;
  void (*func) (struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);
} ndpi_scanner_cdn_t;

typedef struct ndpi_detection_module_struct {
  u_int32_t current_ts;
  u_int32_t ticks_per_second;

  ndpi_scanner_ip_t ndpi_scanners_ip[NDPI_RESULT_IP_LAST];
  ndpi_scanner_base_t ndpi_scanners_base[NDPI_RESULT_BASE_LAST];
  ndpi_scanner_app_t ndpi_scanners_app[NDPI_RESULT_APP_LAST];
  ndpi_scanner_content_t ndpi_scanners_content[NDPI_RESULT_CONTENT_LAST];
  ndpi_scanner_service_t ndpi_scanners_service[NDPI_RESULT_SERVICE_LAST];
  ndpi_scanner_cdn_t ndpi_scanners_cdn[NDPI_RESULT_CDN_LAST];
  
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  void *user_data;

  /* debug callback, only set when debug is used */
  ndpi_debug_function_ptr ndpi_debug_printf;
  const char *ndpi_debug_print_file;
  const char *ndpi_debug_print_function;
  u_int32_t ndpi_debug_print_line;
#endif
  
  /* misc parameters */
  u_int32_t tcp_max_retransmission_window_size;

  /* Pattern matching */
  ndpi_automa http_content_automa, service_automa, cdn_automa;

  u_int32_t directconnect_connection_ip_tick_timeout;
  u_int32_t irc_timeout;
  u_int32_t gnutella_timeout;
  u_int32_t battlefield_timeout;
  u_int32_t thunder_timeout;
  u_int32_t soulseek_connection_ip_tick_timeout;
  u_int8_t yahoo_detect_http_connections;
  u_int32_t yahoo_lan_video_timeout;
  u_int32_t zattoo_connection_timeout;
  u_int32_t jabber_file_transfer_timeout;
  
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
#define NDPI_IP_STRING_SIZE 40
  char ip_string[NDPI_IP_STRING_SIZE];
#endif
  u_int8_t ip_version_limit;

  u_int8_t match_dns_host_names:1;
} ndpi_detection_module_struct_t;

typedef struct ndpi_flow_struct {
  
  /* init parameter, internal used to set up timestamp,... */
  u_int8_t init_finished:1;
  u_int8_t setup_packet_direction:1;
  /* tcp sequence number connection tracking */
  u_int32_t next_tcp_seq_nr[2];

  /* the tcp / udp / other l4 value union
   * this is used to reduce the number of bytes for tcp or udp protocol states
   * */
  union {
    struct ndpi_flow_tcp_struct tcp;
    struct ndpi_flow_udp_struct udp;
  } l4;
  
  ndpi_result_ip_t ndpi_result_ip;
  ndpi_result_base_t ndpi_result_base;
  ndpi_result_app_t ndpi_result_app;
  ndpi_result_content_t ndpi_result_content;
  ndpi_result_service_t ndpi_result_service;
  ndpi_result_cdn_t ndpi_result_cdn;
  
  u_int8_t ndpi_excluded_base[NDPI_RESULT_BASE_LAST];
  u_int8_t ndpi_excluded_app[NDPI_RESULT_APP_LAST];
  u_int8_t ndpi_excluded_service;
  u_int8_t ndpi_excluded_cdn;

  u_char host_server_name[256]; /* HTTP host or DNS query */
  u_char detected_os[32];       /* Via HTTP User-Agent    */
  u_char nat_ip[24];            /* Via HTTP X-Forwarded-For */
  u_char client_certificate[64];
  u_char server_certificate[64];

  union {
    struct {
      u_int8_t num_queries, num_answers, ret_code;
      u_int8_t bad_packet /* the received packet looks bad */;
      u_int16_t query_type, query_class, rsp_type;      
    } dns;
  } protos;
  /* ALL protocol specific 64 bit variables here */

  u_int16_t packet_counter;			// can be 0-65000
  u_int16_t packet_direction_counter[2];
  u_int16_t byte_counter[2];

  u_int8_t bittorrent_stage;		// can be 0-255
  u_int32_t directconnect_stage:2;	// 0-1
  u_int32_t sip_yahoo_voice:1;
  u_int32_t rtsprdt_stage:2;
  u_int32_t rtsp_control_flow:1;
  u_int32_t yahoo_detection_finished:2;
  u_int32_t zattoo_stage:3;
  u_int32_t qq_stage:3;
  u_int32_t thunder_stage:2;		// 0-3
  u_int32_t oscar_ssl_voice_stage:3;
  u_int32_t oscar_video_voice:1;
  u_int32_t florensia_stage:1;
  u_int32_t socks5_stage:2;	// 0-3
  u_int32_t socks4_stage:2;	// 0-3
  u_int32_t edonkey_stage:2;	// 0-3
  u_int32_t ftp_control_stage:2;
  u_int32_t ftp_data_stage:2;
  u_int32_t rtmp_stage:2;
  u_int32_t rtmp_bytes;
  u_int32_t pando_stage:3;
  u_int32_t steam_stage:3;
  u_int32_t steam_stage1:3;			// 0 - 4
  u_int32_t steam_stage2:2;			// 0 - 2
  u_int32_t steam_stage3:2;			// 0 - 2
  u_int32_t pplive_stage1:3;			// 0-6
  u_int32_t pplive_stage2:2;			// 0-2
  u_int32_t pplive_stage3:2;			// 0-2
  u_int8_t redis_s2d_first_char, redis_d2s_first_char;
  u_int32_t http_detected:1;

  /* internal structures to save functions calls */
  struct ndpi_packet_struct packet;
  struct ndpi_flow_struct *flow;
  struct ndpi_id_struct *src;
  struct ndpi_id_struct *dst;
} ndpi_flow_struct_t;

  typedef enum {

    NDPI_LOG_ERROR,
    NDPI_LOG_TRACE,
    NDPI_LOG_DEBUG
  } ndpi_log_level_t;
		     
#endif							/* __NDPI_TYPEDEFS_FILE__ */
