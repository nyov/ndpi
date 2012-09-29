/*
 * ndpi_structs.h
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


#ifndef __NDPI_STRUCTS_INCLUDE_FILE__
#define __NDPI_STRUCTS_INCLUDE_FILE__


# define MAX_PACKET_COUNTER 65000
#ifdef NDPI_DETECTION_SUPPORT_IPV6

struct ndpi_ip6_addr {
	union {
		u8 u6_addr8[16];
		u16 u6_addr16[8];
		u32 u6_addr32[4];
		u64 u6_addr64[2];
	} ndpi_v6_u;

#define ndpi_v6_addr			ndpi_v6_u.u6_addr8
#define ndpi_v6_addr16		ndpi_v6_u.u6_addr16
#define ndpi_v6_addr32		ndpi_v6_u.u6_addr32
#define ndpi_v6_addr64		ndpi_v6_u.u6_addr64
};

struct ndpi_ipv6hdr {
/* use userspace and kernelspace compatible compile parameters */
#if defined(__LITTLE_ENDIAN_BITFIELD) || (defined( __LITTLE_ENDIAN) && __BYTE_ORDER == __LITTLE_ENDIAN)
	u8 priority:4, version:4;
#elif defined(__BIG_ENDIAN_BITFIELD) || (defined( __BIG_ENDIAN) && __BYTE_ORDER == __BIG_ENDIAN)
	u8 version:4, priority:4;
#else
#error	"__LITTLE_ENDIAN_BITFIELD or __BIG_ENDIAN_BITFIELD must be defined, should be done by <asm/byteorder.h>"
#endif

	u8 flow_lbl[3];

	u16 payload_len;
	u8 nexthdr;
	u8 hop_limit;

	struct ndpi_ip6_addr saddr;
	struct ndpi_ip6_addr daddr;
};
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */
typedef union {
	u32 ipv4;
	u8 ipv4_u8[4];
#ifdef NDPI_DETECTION_SUPPORT_IPV6
	struct ndpi_ip6_addr ipv6;
#endif
} ndpi_ip_addr_t;
typedef struct ndpi_id_struct {
	/* detected_protocol_bitmask:
	 * access this bitmask to find out whether an id has used skype or not
	 * if a flag is set here, it will not be resetted
	 * to compare this, use:
	 * if (NDPI_BITMASK_COMPARE(id->detected_protocol_bitmask,
	 *                            NDPI_PROTOCOL_BITMASK_XXX) != 0)
	 * {
	 *      // protocol XXX detected on this id
	 * }
	 */
	NDPI_PROTOCOL_BITMASK detected_protocol_bitmask;
#ifdef NDPI_PROTOCOL_FTP
	ndpi_ip_addr_t ftp_ip;
#endif
#ifdef NDPI_PROTOCOL_RTSP
	ndpi_ip_addr_t rtsp_ip_address;
#endif
#ifdef NDPI_PROTOCOL_PPLIVE
	NDPI_TIMESTAMP_COUNTER_SIZE pplive_last_packet_time;
#endif
#ifdef NDPI_PROTOCOL_SIP
#ifdef NDPI_PROTOCOL_YAHOO
	NDPI_TIMESTAMP_COUNTER_SIZE yahoo_video_lan_timer;
#endif
#endif
#ifdef NDPI_PROTOCOL_IRC
	NDPI_TIMESTAMP_COUNTER_SIZE last_time_port_used[16];
#endif
#ifdef NDPI_PROTOCOL_FTP
	NDPI_TIMESTAMP_COUNTER_SIZE ftp_timer;
#endif
#ifdef NDPI_PROTOCOL_IRC
	NDPI_TIMESTAMP_COUNTER_SIZE irc_ts;
#endif
#ifdef NDPI_PROTOCOL_GNUTELLA
	NDPI_TIMESTAMP_COUNTER_SIZE gnutella_ts;
#endif
#ifdef NDPI_PROTOCOL_BATTLEFIELD
	NDPI_TIMESTAMP_COUNTER_SIZE battlefield_ts;
#endif
#ifdef NDPI_PROTOCOL_THUNDER
	NDPI_TIMESTAMP_COUNTER_SIZE thunder_ts;
#endif
#ifdef NDPI_PROTOCOL_RTSP
	NDPI_TIMESTAMP_COUNTER_SIZE rtsp_timer;
#endif
#ifdef NDPI_PROTOCOL_OSCAR
	NDPI_TIMESTAMP_COUNTER_SIZE oscar_last_safe_access_time;
#endif
#ifdef NDPI_PROTOCOL_GADUGADU
	u32 gg_ft_ip_address;
	NDPI_TIMESTAMP_COUNTER_SIZE gg_timeout;
#endif
#ifdef NDPI_PROTOCOL_ZATTOO
	NDPI_TIMESTAMP_COUNTER_SIZE zattoo_ts;
#endif
#ifdef NDPI_PROTOCOL_UNENCRYPED_JABBER
	NDPI_TIMESTAMP_COUNTER_SIZE jabber_stun_or_ft_ts;
#endif
#ifdef NDPI_PROTOCOL_MANOLITO
	u32 manolito_last_pkt_arrival_time;
#endif
#ifdef NDPI_PROTOCOL_DIRECTCONNECT
	NDPI_TIMESTAMP_COUNTER_SIZE directconnect_last_safe_access_time;
#endif
#ifdef NDPI_PROTOCOL_SOULSEEK
	NDPI_TIMESTAMP_COUNTER_SIZE soulseek_last_safe_access_time;
#endif
#ifdef NDPI_PROTOCOL_DIRECTCONNECT
	u16 detected_directconnect_port;
	u16 detected_directconnect_udp_port;
	u16 detected_directconnect_ssl_port;
#endif
#ifdef NDPI_PROTOCOL_PPLIVE
	u16 pplive_vod_cli_port;
#endif
#ifdef NDPI_PROTOCOL_IRC
	u16 irc_port[16];
#endif
#ifdef NDPI_PROTOCOL_GADUGADU
	u16 gg_ft_port;
#endif
#ifdef NDPI_PROTOCOL_UNENCRYPED_JABBER
#define JABBER_MAX_STUN_PORTS 6
	u16 jabber_voice_stun_port[JABBER_MAX_STUN_PORTS];
	u16 jabber_file_transfer_port[2];
#endif
#ifdef NDPI_PROTOCOL_GNUTELLA
	u16 detected_gnutella_port;
#endif
#ifdef NDPI_PROTOCOL_GNUTELLA
	u16 detected_gnutella_udp_port1;
	u16 detected_gnutella_udp_port2;
#endif
#ifdef NDPI_PROTOCOL_SOULSEEK
	u16 soulseek_listen_port;
#endif
#ifdef NDPI_PROTOCOL_IRC
	u8 irc_number_of_port;
#endif
#ifdef NDPI_PROTOCOL_OSCAR
	u8 oscar_ssl_session_id[33];
#endif
#ifdef NDPI_PROTOCOL_GADUGADU
	u8 gg_call_id[2][7];
	u8 gg_fmnumber[8];
#endif
#ifdef NDPI_PROTOCOL_UNENCRYPED_JABBER
	u8 jabber_voice_stun_used_ports;
#endif
#ifdef NDPI_PROTOCOL_SIP
#ifdef NDPI_PROTOCOL_YAHOO
	u32 yahoo_video_lan_dir:1;
#endif
#endif
#ifdef NDPI_PROTOCOL_YAHOO
	u32 yahoo_conf_logged_in:1;
	u32 yahoo_voice_conf_logged_in:1;
#endif
#ifdef NDPI_PROTOCOL_FTP
	u32 ftp_timer_set:1;
#endif
#ifdef NDPI_PROTOCOL_GADUGADU
	u32 gadu_gadu_ft_direction:1;
	u32 gadu_gadu_voice:1;
	u32 gg_next_id:1;
#endif
#ifdef NDPI_PROTOCOL_RTSP
	u32 rtsp_ts_set:1;
#endif
#ifdef NDPI_PROTOCOL_PPLIVE
	u32 pplive_last_packet_time_set:1;
#endif
} ndpi_id_struct;
struct ndpi_flow_tcp_struct {
#ifdef NDPI_PROTOCOL_FLASH
	u16 flash_bytes;
#endif
#ifdef NDPI_PROTOCOL_MAIL_SMTP
	u16 smtp_command_bitmask;
#endif
#ifdef NDPI_PROTOCOL_MAIL_POP
	u16 pop_command_bitmask;
#endif
#ifdef NDPI_PROTOCOL_QQ
	u16 qq_nxt_len;
#endif
#ifdef NDPI_PROTOCOL_TDS
	u8 tds_login_version;
#endif
#ifdef NDPI_PROTOCOL_PPLIVE
	u8 pplive_next_packet_size[2];
#endif
#ifdef NDPI_PROTOCOL_IRC
	u8 irc_stage;
	u8 irc_port;
#endif
#ifdef NDPI_PROTOCOL_GNUTELLA
	u8 gnutella_msg_id[3];
#endif
#ifdef NDPI_PROTOCOL_EDONKEY
	u32 edk_ext:1;
#endif
#ifdef NDPI_PROTOCOL_IRC
	u32 irc_3a_counter:3;
	u32 irc_stage2:5;
	u32 irc_direction:2;
	u32 irc_0x1000_full:1;
#endif
#ifdef NDPI_PROTOCOL_WINMX
	u32 winmx_stage:1;			// 0-1
#endif
#ifdef NDPI_PROTOCOL_SOULSEEK
	u32 soulseek_stage:2;
#endif
#ifdef NDPI_PROTOCOL_FILETOPIA
	u32 filetopia_stage:2;
#endif
#ifdef NDPI_PROTOCOL_MANOLITO
	u32 manolito_stage:4;
#endif
#ifdef NDPI_PROTOCOL_TDS
	u32 tds_stage:3;
#endif
#ifdef NDPI_PROTOCOL_GADUGADU
	u32 gadugadu_stage:2;
#endif
#ifdef NDPI_PROTOCOL_USENET
	u32 usenet_stage:2;
#endif
#ifdef NDPI_PROTOCOL_IMESH
	u32 imesh_stage:4;
#endif
#ifdef NDPI_PROTOCOL_FTP
	u32 ftp_codes_seen:5;
	u32 ftp_client_direction:1;
#endif
#ifdef NDPI_PROTOCOL_HTTP
	u32 http_setup_dir:2;
	u32 http_stage:2;
	u32 http_empty_line_seen:1;
	u32 http_wait_for_retransmission:1;
#endif							// NDPI_PROTOCOL_HTTP
#ifdef NDPI_PROTOCOL_FLASH
	u32 flash_stage:3;
#endif
#ifdef NDPI_PROTOCOL_GNUTELLA
	u32 gnutella_stage:2;		//0-2
#endif
#ifdef NDPI_PROTOCOL_MMS
	u32 mms_stage:2;
#endif
#ifdef NDPI_PROTOCOL_YAHOO
	u32 yahoo_sip_comm:1;
	u32 yahoo_http_proxy_stage:2;
#endif
#ifdef NDPI_PROTOCOL_MSN
	u32 msn_stage:3;
	u32 msn_ssl_ft:2;
#endif
#ifdef NDPI_PROTOCOL_SSH
	u32 ssh_stage:3;
#endif
#ifdef NDPI_PROTOCOL_VNC
	u32 vnc_stage:2;			// 0 - 3
#endif
#ifdef NDPI_PROTOCOL_STEAM
	u32 steam_stage:2;			// 0 - 3
#endif
#ifdef NDPI_PROTOCOL_TELNET
	u32 telnet_stage:2;			// 0 - 2
#endif
#ifdef NDPI_PROTOCOL_SSL
	u32 ssl_stage:2;			// 0 - 3
#endif
#ifdef NDPI_PROTOCOL_POSTGRES
	u32 postgres_stage:3;
#endif
#ifdef NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK
	u32 ddlink_server_direction:1;
#endif
	u32 seen_syn:1;
	u32 seen_syn_ack:1;
	u32 seen_ack:1;
#ifdef NDPI_PROTOCOL_ICECAST
	u32 icecast_stage:1;
#endif
#ifdef NDPI_PROTOCOL_DOFUS
	u32 dofus_stage:1;
#endif
#ifdef NDPI_PROTOCOL_FIESTA
	u32 fiesta_stage:2;
#endif
#ifdef NDPI_PROTOCOL_WORLDOFWARCRAFT
	u32 wow_stage:2;
#endif
#ifdef NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV
	u32 veoh_tv_stage:2;
#endif
#ifdef NDPI_PROTOCOL_SHOUTCAST
	u32 shoutcast_stage:2;
#endif
#ifdef NDPI_PROTOCOL_RTP
	u32 rtp_special_packets_seen:1;
#endif
#ifdef NDPI_PROTOCOL_MAIL_POP
	u32 mail_pop_stage:2;
#endif
#ifdef NDPI_PROTOCOL_MAIL_IMAP
	u32 mail_imap_stage:3;
#endif

#ifdef NTOP_PROTOCOL_SKYPE
  u8 skype_packet_id;
#endif

#ifdef NTOP_PROTOCOL_CITRIX
  u8 citrix_packet_id;
#endif

#ifdef NTOP_PROTOCOL_TEAMVIEWER
  u8 teamviewer_stage;
#endif
} 

#if !(defined(HAVE_NTOP) && defined(WIN32))
__attribute__ ((__packed__))
#endif
;

struct ndpi_flow_udp_struct {
#ifdef NDPI_PROTOCOL_BATTLEFIELD
	u32 battlefield_msg_id;
#endif
#ifdef NDPI_PROTOCOL_SNMP
	u32 snmp_msg_id;
#endif
#ifdef NDPI_PROTOCOL_BATTLEFIELD
	u32 battlefield_stage:3;
#endif
#ifdef NDPI_PROTOCOL_SNMP
	u32 snmp_stage:2;
#endif
#ifdef NDPI_PROTOCOL_PPSTREAM
	u32 ppstream_stage:3;		// 0-7
#endif
#ifdef NDPI_PROTOCOL_FEIDIAN
	u32 feidian_stage:1;		// 0-7
#endif
#ifdef NDPI_PROTOCOL_HALFLIFE2
	u32 halflife2_stage:2;		// 0 - 2
#endif
#ifdef NDPI_PROTOCOL_TFTP
	u32 tftp_stage:1;
#endif
#ifdef NDPI_PROTOCOL_AIMINI
	u32 aimini_stage:5;
#endif
#ifdef NDPI_PROTOCOL_XBOX
	u32 xbox_stage:1;
#endif
#ifdef NTOP_PROTOCOL_WINDOWS_UPDATE
  u32 wsus_stage:1;
#endif
#ifdef NTOP_PROTOCOL_SKYPE
  u8 skype_packet_id;
#endif
#ifdef NTOP_PROTOCOL_TEAMVIEWER
  u8 teamviewer_stage;
#endif
}

#if !(defined(HAVE_NTOP) && defined(WIN32))
__attribute__ ((__packed__))
#endif
	;


typedef struct ndpi_flow_struct {

	u16 detected_protocol_stack[NDPI_PROTOCOL_HISTORY_SIZE];
#if NDPI_PROTOCOL_HISTORY_SIZE > 1
#  if NDPI_PROTOCOL_HISTORY_SIZE > 5
#    error protocol stack size not supported
#  endif

	struct {
		u8 entry_is_real_protocol:5;
		u8 current_stack_size_minus_one:3;
	} 

#if !(defined(HAVE_NTOP) && defined(WIN32))
__attribute__ ((__packed__))
#endif
	protocol_stack_info;
#endif


	/* init parameter, internal used to set up timestamp,... */
	u8 init_finished:1;
	u8 setup_packet_direction:1;
/* tcp sequence number connection tracking */
	u32 next_tcp_seq_nr[2];

	/* the tcp / udp / other l4 value union
	 * this is used to reduce the number of bytes for tcp or udp protocol states
	 * */
	union {
		struct ndpi_flow_tcp_struct tcp;
		struct ndpi_flow_udp_struct udp;
	} l4;


/* ALL protocol specific 64 bit variables here */

	/* protocols which have marked a connection as this connection cannot be protocol XXX, multiple u64 */
	NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;

#ifdef NDPI_PROTOCOL_RTP
	u32 rtp_ssid[2];
#endif
#ifdef NDPI_PROTOCOL_I23V5
	u32 i23v5_len1;
	u32 i23v5_len2;
	u32 i23v5_len3;
#endif
	u16 packet_counter;			// can be 0-65000
	u16 packet_direction_counter[2];
	u16 byte_counter[2];
#ifdef NDPI_PROTOCOL_RTP
	u16 rtp_seqnum[2];			/* current highest sequence number (only goes forwards, is not decreased by retransmissions) */
#endif
#ifdef NDPI_PROTOCOL_RTP
	/* tcp and udp */
	u8 rtp_payload_type[2];
#endif

#ifdef NDPI_PROTOCOL_BITTORRENT
	u8 bittorrent_stage;		// can be 0-255
#endif
#ifdef NDPI_PROTOCOL_RTP
	u32 rtp_stage1:2;			//0-3
	u32 rtp_stage2:2;
#endif
#ifdef NDPI_PROTOCOL_EDONKEY
	u32 edk_stage:5;			// 0-17
#endif
#ifdef NDPI_PROTOCOL_DIRECTCONNECT
	u32 directconnect_stage:2;	// 0-1
#endif
#ifdef NDPI_PROTOCOL_SIP
#ifdef NDPI_PROTOCOL_YAHOO
	u32 sip_yahoo_voice:1;
#endif
#endif
#ifdef NDPI_PROTOCOL_HTTP
	u32 http_detected:1;
#endif							// NDPI_PROTOCOL_HTTP
#ifdef NDPI_PROTOCOL_RTSP
	u32 rtsprdt_stage:2;
	u32 rtsp_control_flow:1;
#endif

#ifdef NDPI_PROTOCOL_YAHOO
	u32 yahoo_detection_finished:2;
#endif
#ifdef NDPI_PROTOCOL_PPLIVE
	u32 pplive_stage:3;			// 0-7
#endif

#ifdef NDPI_PROTOCOL_ZATTOO
	u32 zattoo_stage:3;
#endif
#ifdef NDPI_PROTOCOL_QQ
	u32 qq_stage:3;
#endif
#ifdef NDPI_PROTOCOL_THUNDER
	u32 thunder_stage:2;		// 0-3
#endif
#ifdef NDPI_PROTOCOL_OSCAR
	u32 oscar_ssl_voice_stage:3;
	u32 oscar_video_voice:1;
#endif
#ifdef NDPI_PROTOCOL_FLORENSIA
	u32 florensia_stage:1;
#endif
} ndpi_flow_struct_t;
#endif							/* __NDPI_STRUCTS_INCLUDE_FILE__ */
