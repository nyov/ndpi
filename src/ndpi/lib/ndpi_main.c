/*
 * ndpi_main.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-14 - ntop.org
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


#ifndef __KERNEL__
#include <stdlib.h>
#include <errno.h>
#endif

#include "ndpi_api.h"

#ifndef __KERNEL__
#include "../../../config.h"
#endif

#undef DEBUG

#ifdef __KERNEL__
#include <linux/version.h>
#define printf printk
#else
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#endif
#endif

#include "ndpi_general_functions.c"


/* ****************************************** */

u_int32_t ndpi_detection_get_sizeof_ndpi_flow_struct(void)
{
  return sizeof(struct ndpi_flow_struct);
}

/* ****************************************** */

u_int32_t ndpi_detection_get_sizeof_ndpi_id_struct(void)
{
  return sizeof(struct ndpi_id_struct);
}

/* ******************************************************************** */

struct ndpi_flow_struct *create_ndpi_flow_struct_pointer(void) {
  return ndpi_calloc(1, ndpi_detection_get_sizeof_ndpi_flow_struct());
}

void clear_ndpi_flow_struct_pointer(struct ndpi_flow_struct *ndpi_flow_struct_pointer) {
  memset(ndpi_flow_struct_pointer, 0, ndpi_detection_get_sizeof_ndpi_flow_struct());
}

void delete_ndpi_flow_struct_pointer(struct ndpi_flow_struct *ndpi_flow_struct_pointer) {
  free(ndpi_flow_struct_pointer);
  ndpi_flow_struct_pointer = NULL;
}

/* ******************************************************************** */

ndpi_result_ip_t ndpi_get_result_ip_id (struct ndpi_flow_struct *ndpi_flow_struct_pointer) {
  return ndpi_flow_struct_pointer->ndpi_result_ip;
}

ndpi_result_base_t ndpi_get_result_base_id (struct ndpi_flow_struct *ndpi_flow_struct_pointer) {
  return ndpi_flow_struct_pointer->ndpi_result_base;
}

ndpi_result_app_t ndpi_get_result_app_id (struct ndpi_flow_struct *ndpi_flow_struct_pointer) {
  return ndpi_flow_struct_pointer->ndpi_result_app;
}

ndpi_result_content_t ndpi_get_result_content_id (struct ndpi_flow_struct *ndpi_flow_struct_pointer) {
  return ndpi_flow_struct_pointer->ndpi_result_content;
}

ndpi_result_service_t ndpi_get_result_service_id (struct ndpi_flow_struct *ndpi_flow_struct_pointer) {
  return ndpi_flow_struct_pointer->ndpi_result_service;
}

ndpi_result_cdn_t ndpi_get_result_cdn_id (struct ndpi_flow_struct *ndpi_flow_struct_pointer) {
  return ndpi_flow_struct_pointer->ndpi_result_cdn;
}

/* ******************************************************************** */

char *ndpi_get_result_ip_name (struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *ndpi_flow_struct_pointer) {
  return ndpi_mod->ndpi_scanners_ip[ndpi_flow_struct_pointer->ndpi_result_ip].name;
}

char *ndpi_get_result_base_name (struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *ndpi_flow_struct_pointer) {
  return ndpi_mod->ndpi_scanners_base[ndpi_flow_struct_pointer->ndpi_result_base].name;
}

char *ndpi_get_result_app_name (struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *ndpi_flow_struct_pointer) {
  return ndpi_mod->ndpi_scanners_app[ndpi_flow_struct_pointer->ndpi_result_app].name;
}

char *ndpi_get_result_content_name (struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *ndpi_flow_struct_pointer) {
  return ndpi_mod->ndpi_scanners_content[ndpi_flow_struct_pointer->ndpi_result_content].name;
}

char *ndpi_get_result_service_name (struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *ndpi_flow_struct_pointer) {
  return ndpi_mod->ndpi_scanners_service[ndpi_flow_struct_pointer->ndpi_result_service].name;
}

char *ndpi_get_result_cdn_name (struct ndpi_detection_module_struct *ndpi_mod, struct ndpi_flow_struct *ndpi_flow_struct_pointer) {
  return ndpi_mod->ndpi_scanners_cdn[ndpi_flow_struct_pointer->ndpi_result_cdn].name;
}

/* ******************************************************************** */

void ndpi_initialize_scanner_ip (struct ndpi_detection_module_struct *mod, ndpi_result_ip_t id, char *name, void (*func)) {
  mod->ndpi_scanners_ip[id].id = id;
  mod->ndpi_scanners_ip[id].name = name;
  mod->ndpi_scanners_ip[id].func = func;
}

void ndpi_initialize_scanner_base (struct ndpi_detection_module_struct *mod,
				   ndpi_result_base_t id, char *name,
				   NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet,
				   int *default_tcp_ports,
				   int *default_udp_ports,
				   void (*func)) {
  int i;
  
  mod->ndpi_scanners_base[id].id = id;
  mod->ndpi_scanners_base[id].name = name;
  mod->ndpi_scanners_base[id].ndpi_selection_packet = ndpi_selection_packet;
  mod->ndpi_scanners_base[id].func = func;
  
  for (i = 0; i< 5; i++) {
    mod->ndpi_scanners_base[id].default_tcp_ports[i] = default_tcp_ports[i];
    mod->ndpi_scanners_base[id].default_udp_ports[i] = default_udp_ports[i];
  }
  
}

void ndpi_initialize_scanner_app (struct ndpi_detection_module_struct *mod, ndpi_result_app_t id,
				  char *name,
				  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet,
				  int *default_tcp_ports,
				  int *default_udp_ports,
				  void (*func)) {
  int i;
  
  mod->ndpi_scanners_app[id].id = id;
  mod->ndpi_scanners_app[id].name = name;
  mod->ndpi_scanners_app[id].ndpi_selection_packet = ndpi_selection_packet;
  mod->ndpi_scanners_app[id].func = func;
  
  for (i = 0; i < 5; i++) {
    mod->ndpi_scanners_app[id].default_tcp_ports[i] = default_tcp_ports[i];
    mod->ndpi_scanners_app[id].default_udp_ports[i] = default_udp_ports[i];
  }
  
}

void ndpi_initialize_scanner_content (struct ndpi_detection_module_struct *mod, ndpi_result_content_t id, char *name, void (*func)) {
  mod->ndpi_scanners_content[id].id = id;
  mod->ndpi_scanners_content[id].name = name;
  mod->ndpi_scanners_content[id].func = func;
}

void ndpi_initialize_scanner_service (struct ndpi_detection_module_struct *mod, ndpi_result_service_t id, char *name, void (*func)) {
  mod->ndpi_scanners_service[id].id = id;
  mod->ndpi_scanners_service[id].name = name;
  mod->ndpi_scanners_service[id].func = func;
}

void ndpi_initialize_scanner_cdn (struct ndpi_detection_module_struct *mod, ndpi_result_cdn_t id, char *name, void (*func)) {
  mod->ndpi_scanners_cdn[id].id = id;
  mod->ndpi_scanners_cdn[id].name = name;
  mod->ndpi_scanners_cdn[id].func = func;
}

struct ndpi_detection_module_struct *create_ndpi_detection_module_struct_pointer(u_int32_t ticks_per_second,
								ndpi_debug_function_ptr ndpi_debug_printf)
{
  struct ndpi_detection_module_struct *ndpi_mod;

  ndpi_mod = malloc(sizeof(struct ndpi_detection_module_struct));

  if(ndpi_mod == NULL) {
    ndpi_debug_printf(0, NULL, NDPI_LOG_DEBUG, "create_ndpi_detection_module_struct_pointer initial malloc failed\n");
    return NULL;
  }
  
  memset(ndpi_mod, 0, sizeof(struct ndpi_detection_module_struct));
  
#ifdef NDPI_ENABLE_DEBUG_MESSAGES
  ndpi_mod->ndpi_debug_printf = ndpi_debug_printf;
  ndpi_mod->user_data = NULL;
#endif

  ndpi_mod->ticks_per_second = ticks_per_second;
  ndpi_mod->tcp_max_retransmission_window_size = NDPI_DEFAULT_MAX_TCP_RETRANSMISSION_WINDOW_SIZE;
  ndpi_mod->directconnect_connection_ip_tick_timeout = NDPI_DIRECTCONNECT_CONNECTION_IP_TICK_TIMEOUT * ticks_per_second;

  ndpi_mod->irc_timeout = NDPI_IRC_CONNECTION_TIMEOUT * ticks_per_second;
  ndpi_mod->gnutella_timeout = NDPI_GNUTELLA_CONNECTION_TIMEOUT * ticks_per_second;

  ndpi_mod->battlefield_timeout = NDPI_BATTLEFIELD_CONNECTION_TIMEOUT * ticks_per_second;

  ndpi_mod->thunder_timeout = NDPI_THUNDER_CONNECTION_TIMEOUT * ticks_per_second;
  ndpi_mod->yahoo_detect_http_connections = NDPI_YAHOO_DETECT_HTTP_CONNECTIONS;

  ndpi_mod->yahoo_lan_video_timeout = NDPI_YAHOO_LAN_VIDEO_TIMEOUT * ticks_per_second;
  ndpi_mod->zattoo_connection_timeout = NDPI_ZATTOO_CONNECTION_TIMEOUT * ticks_per_second;
  ndpi_mod->jabber_file_transfer_timeout = NDPI_JABBER_FT_TIMEOUT * ticks_per_second;
  ndpi_mod->soulseek_connection_ip_tick_timeout = NDPI_SOULSEEK_CONNECTION_IP_TICK_TIMEOUT * ticks_per_second;
  
  /* The masks below are set to 255 (11111111) to exclude the protocols from any search.
   * We do not have any default TCP or UDP ports here as well.
   */
  
  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};
  
  ndpi_initialize_scanner_ip (ndpi_mod, NDPI_RESULT_IP_STILL_UNKNOWN, "still_unknown", NULL);
  ndpi_initialize_scanner_base (ndpi_mod, NDPI_RESULT_BASE_STILL_UNKNOWN, "still_unknown", 255, tcp_ports, udp_ports, NULL);
  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_STILL_UNKNOWN, "still_unknown", 255, tcp_ports, udp_ports, NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_STILL_UNKNOWN, "still_unknown", NULL);
  ndpi_initialize_scanner_service (ndpi_mod, NDPI_RESULT_SERVICE_STILL_UNKNOWN, "still_unknown", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_STILL_UNKNOWN, "still_unknown", NULL);
  
  ndpi_initialize_scanner_ip (ndpi_mod, NDPI_RESULT_IP_UNKNOWN, "unknown", NULL);
  ndpi_initialize_scanner_base (ndpi_mod, NDPI_RESULT_BASE_UNKNOWN, "unknown", 255, tcp_ports, udp_ports, NULL);
  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_UNKNOWN, "unknown", 255, tcp_ports, udp_ports, NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_UNKNOWN, "unknown", NULL);
  ndpi_initialize_scanner_service (ndpi_mod, NDPI_RESULT_SERVICE_UNKNOWN, "unknown", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_UNKNOWN, "unknown", NULL);
  
  ndpi_register_ip_protocols (ndpi_mod);
  
  ndpi_register_proto_ciscovpn (ndpi_mod);
  ndpi_register_proto_http (ndpi_mod);
  ndpi_register_proto_openvpn (ndpi_mod);
  ndpi_register_proto_socks4 (ndpi_mod);
  ndpi_register_proto_socks5 (ndpi_mod);
  ndpi_register_proto_ssl (ndpi_mod);
  ndpi_register_proto_tor (ndpi_mod);
  ndpi_register_proto_bittorrent (ndpi_mod);
  ndpi_register_proto_dns (ndpi_mod);
  ndpi_register_proto_imap (ndpi_mod);
  ndpi_register_proto_pop (ndpi_mod);
  ndpi_register_proto_smtp (ndpi_mod);
  ndpi_register_proto_ssl_based (ndpi_mod);
  ndpi_register_proto_edonkey (ndpi_mod);
  ndpi_register_proto_ftp_control (ndpi_mod);
  ndpi_register_proto_ftp_data (ndpi_mod);
  ndpi_register_proto_netbios (ndpi_mod);
  ndpi_register_proto_ntp (ndpi_mod);
  ndpi_register_proto_pando (ndpi_mod);
  ndpi_register_proto_pplive (ndpi_mod);
  ndpi_register_proto_rdp (ndpi_mod);
  ndpi_register_proto_rtmp (ndpi_mod);
  ndpi_register_proto_skype (ndpi_mod);
  ndpi_register_proto_smb (ndpi_mod);
  ndpi_register_proto_sopcast (ndpi_mod);
  ndpi_register_proto_ssh (ndpi_mod);
  ndpi_register_proto_steam (ndpi_mod);
  ndpi_register_proto_dropbox (ndpi_mod);
  ndpi_register_proto_ppstream (ndpi_mod);
  ndpi_register_proto_spotify (ndpi_mod);
  ndpi_register_proto_various_directdownloadlink (ndpi_mod);
  ndpi_register_proto_world_of_warcraft (ndpi_mod);
  ndpi_register_proto_bgp (ndpi_mod);
  ndpi_register_proto_dhcp (ndpi_mod);
  ndpi_register_proto_dhcpv6 (ndpi_mod);
  ndpi_register_proto_directconnect (ndpi_mod);
  ndpi_register_proto_fasttrack (ndpi_mod);
  ndpi_register_proto_gnutella (ndpi_mod);
  ndpi_register_proto_imesh (ndpi_mod);
  ndpi_register_proto_netflow (ndpi_mod);
  ndpi_register_proto_nfs (ndpi_mod);
  ndpi_register_proto_rtp (ndpi_mod);
  ndpi_register_proto_sip (ndpi_mod);
  ndpi_register_proto_snmp (ndpi_mod);
  ndpi_register_proto_teamviewer (ndpi_mod);
  ndpi_register_proto_telnet (ndpi_mod);
  ndpi_register_proto_tftp (ndpi_mod);
  ndpi_register_proto_usenet (ndpi_mod);
  ndpi_register_proto_vmware (ndpi_mod);
  ndpi_register_proto_vnc (ndpi_mod);
  ndpi_register_proto_warcraft3 (ndpi_mod);
  ndpi_register_proto_yahoo_messenger (ndpi_mod);
  ndpi_register_proto_megaco (ndpi_mod);
  ndpi_register_proto_redis (ndpi_mod);
  ndpi_register_proto_zmq (ndpi_mod);
  ndpi_register_proto_afp (ndpi_mod);
  ndpi_register_proto_applejuice (ndpi_mod);
  ndpi_register_proto_ayiya (ndpi_mod);
  ndpi_register_proto_collectd (ndpi_mod);
  ndpi_register_proto_corba (ndpi_mod);
  ndpi_register_proto_dcerpc (ndpi_mod);
  ndpi_register_proto_gtp (ndpi_mod);
  ndpi_register_proto_guildwars (ndpi_mod);
  ndpi_register_proto_h323 (ndpi_mod);
  ndpi_register_proto_halflife2_and_mods (ndpi_mod);
  ndpi_register_proto_http_activesync (ndpi_mod);
  ndpi_register_proto_kerberos (ndpi_mod);
  ndpi_register_proto_kontiki (ndpi_mod);
  ndpi_register_proto_mssql (ndpi_mod);
  ndpi_register_proto_mysql (ndpi_mod);
  ndpi_register_proto_noe (ndpi_mod);
  ndpi_register_proto_openft (ndpi_mod);
  ndpi_register_proto_oracle (ndpi_mod);
  ndpi_register_proto_pcanywhere (ndpi_mod);
  ndpi_register_proto_pptp (ndpi_mod);
  ndpi_register_proto_radius (ndpi_mod);
  ndpi_register_proto_rsync (ndpi_mod);
  ndpi_register_proto_rtcp (ndpi_mod);
  ndpi_register_proto_rtsp (ndpi_mod);
  ndpi_register_proto_sflow (ndpi_mod);
  ndpi_register_proto_ssdp (ndpi_mod);
  ndpi_register_proto_stealthnet (ndpi_mod);
  ndpi_register_proto_tds (ndpi_mod);
  ndpi_register_proto_viber (ndpi_mod);
  ndpi_register_proto_whoisdas (ndpi_mod);
  ndpi_register_proto_world_of_kung_fu (ndpi_mod);
  ndpi_register_proto_xdmcp (ndpi_mod);
  ndpi_register_proto_aimini (ndpi_mod);
  ndpi_register_proto_armagetron (ndpi_mod);
  ndpi_register_proto_battlefield (ndpi_mod);
  ndpi_register_proto_citrix (ndpi_mod);
  ndpi_register_proto_crossfire (ndpi_mod);
  ndpi_register_proto_dofus (ndpi_mod);
  ndpi_register_proto_fiesta (ndpi_mod);
  ndpi_register_proto_filetopia (ndpi_mod);
  ndpi_register_proto_florensia (ndpi_mod);
  ndpi_register_proto_iax (ndpi_mod);
  ndpi_register_proto_icecast (ndpi_mod);
  ndpi_register_proto_ipp (ndpi_mod);
  ndpi_register_proto_irc (ndpi_mod);
  ndpi_register_proto_jabber (ndpi_mod);
  ndpi_register_proto_ldap (ndpi_mod);
  ndpi_register_proto_lotus_notes (ndpi_mod);
  ndpi_register_proto_maplestory (ndpi_mod);
  ndpi_register_proto_mdns (ndpi_mod);
  ndpi_register_proto_meebo (ndpi_mod);
  ndpi_register_proto_mgcp (ndpi_mod);
  ndpi_register_proto_msn (ndpi_mod);
  ndpi_register_proto_oscar (ndpi_mod);
  ndpi_register_proto_postgres (ndpi_mod);
  ndpi_register_proto_qq (ndpi_mod);
  ndpi_register_proto_quake (ndpi_mod);
  ndpi_register_proto_shoutcast (ndpi_mod);
  ndpi_register_proto_skinny (ndpi_mod);
  ndpi_register_proto_skyfile (ndpi_mod);
  ndpi_register_proto_socrates (ndpi_mod);
  ndpi_register_proto_soulseek (ndpi_mod);
  ndpi_register_proto_stun (ndpi_mod);
  ndpi_register_proto_syslog (ndpi_mod);
  ndpi_register_proto_teamspeak (ndpi_mod);
  ndpi_register_proto_thunder (ndpi_mod);
  ndpi_register_proto_tvants (ndpi_mod);
  ndpi_register_proto_tvuplayer (ndpi_mod);
  ndpi_register_proto_veohtv (ndpi_mod);
  ndpi_register_proto_vhua (ndpi_mod);
  ndpi_register_proto_windows_update (ndpi_mod);
  ndpi_register_proto_winmx (ndpi_mod);
  ndpi_register_proto_xbox (ndpi_mod);
  ndpi_register_proto_zattoo (ndpi_mod);
  
  ndpi_register_content_raw (ndpi_mod);
  ndpi_register_content_http (ndpi_mod);
  
  ndpi_register_service_parser (ndpi_mod);
  ndpi_register_cdn_parser (ndpi_mod);

  return ndpi_mod;
}

/* ****************************************************** */

void delete_ndpi_detection_module_struct_pointer(struct ndpi_detection_module_struct *ndpi_struct)
{
  if(ndpi_struct != NULL) {
    ndpi_unregister_content_http (ndpi_struct);
    ndpi_unregister_service_parser (ndpi_struct);
    ndpi_unregister_cdn_parser (ndpi_struct);
    free(ndpi_struct);
  }
}

/* ******************************************************************** */

#ifdef NDPI_DETECTION_SUPPORT_IPV6
/* handle extension headers in IPv6 packets
 * arguments:
 * 	l4ptr: pointer to the byte following the initial IPv6 header
 * 	l4len: the length of the IPv6 packet excluding the IPv6 header
 * 	nxt_hdr: next header value from the IPv6 header
 * result:
 * 	l4ptr: pointer to the start of the actual packet payload
 * 	l4len: length of the actual payload
 * 	nxt_hdr: protocol of the actual payload
 * returns 0 upon success and 1 upon failure
 */
static int ndpi_handle_ipv6_extension_headers(struct ndpi_detection_module_struct *ndpi_struct,
					      const u_int8_t ** l4ptr, u_int16_t * l4len, u_int8_t * nxt_hdr)
{
  while ((*nxt_hdr == 0 || *nxt_hdr == 43 || *nxt_hdr == 44 || *nxt_hdr == 60 || *nxt_hdr == 135 || *nxt_hdr == 59)) {
    u_int16_t ehdr_len;

    // no next header
    if(*nxt_hdr == 59) {
      return 1;
    }
    // fragment extension header has fixed size of 8 bytes and the first byte is the next header type
    if(*nxt_hdr == 44) {
      if(*l4len < 8) {
	return 1;
      }
      *nxt_hdr = (*l4ptr)[0];
      *l4len -= 8;
      (*l4ptr) += 8;
      continue;
    }
    // the other extension headers have one byte for the next header type
    // and one byte for the extension header length in 8 byte steps minus the first 8 bytes
    ehdr_len = (*l4ptr)[1];
    ehdr_len *= 8;
    ehdr_len += 8;

    if(*l4len < ehdr_len) {
      return 1;
    }
    *nxt_hdr = (*l4ptr)[0];
    *l4len -= ehdr_len;
    (*l4ptr) += ehdr_len;
  }
  return 0;
}
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */


static u_int8_t ndpi_iph_is_valid_and_not_fragmented(const struct ndpi_iphdr *iph, const u_int16_t ipsize)
{
  if(ipsize < iph->ihl * 4 ||
     ipsize < ntohs(iph->tot_len) || ntohs(iph->tot_len) < iph->ihl * 4 || (iph->frag_off & htons(0x1FFF)) != 0) {
    return 0;
  }

  return 1;
}

static u_int8_t ndpi_detection_get_l4_internal(struct ndpi_detection_module_struct *ndpi_struct,
					       const u_int8_t * l3, u_int16_t l3_len, const u_int8_t ** l4_return, u_int16_t * l4_len_return,
					       u_int8_t * l4_protocol_return, u_int32_t flags)
{
  const struct ndpi_iphdr *iph = NULL;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  const struct ndpi_ipv6hdr *iph_v6 = NULL;
#endif
  u_int16_t l4len = 0;
  const u_int8_t *l4ptr = NULL;
  u_int8_t l4protocol = 0;

  if(l3 == NULL || l3_len < sizeof(struct ndpi_iphdr))
    return 1;

  iph = (const struct ndpi_iphdr *) l3;

  if(iph->version == 4 && iph->ihl >= 5) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "ipv4 header\n");
  }
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  else if(iph->version == 6 && l3_len >= sizeof(struct ndpi_ipv6hdr)) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "ipv6 header\n");
    iph_v6 = (const struct ndpi_ipv6hdr *) iph;
    iph = NULL;
  }
#endif
  else {
    return 1;
  }

  if((flags & NDPI_DETECTION_ONLY_IPV6) && iph != NULL) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "ipv4 header found but excluded by flag\n");
    return 1;
  }
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  else if((flags & NDPI_DETECTION_ONLY_IPV4) && iph_v6 != NULL) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "ipv6 header found but excluded by flag\n");
    return 1;
  }
#endif

  if(iph != NULL && ndpi_iph_is_valid_and_not_fragmented(iph, l3_len)) {
    u_int16_t len  = ntohs(iph->tot_len);
    u_int16_t hlen = (iph->ihl * 4);

    l4ptr = (((const u_int8_t *) iph) + iph->ihl * 4);

    if(len == 0) len = l3_len;

    l4len = (len > hlen) ? (len - hlen) : 0;
    l4protocol = iph->protocol;
  }
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  else if(iph_v6 != NULL && (l3_len - sizeof(struct ndpi_ipv6hdr)) >= ntohs(iph_v6->payload_len)) {
    l4ptr = (((const u_int8_t *) iph_v6) + sizeof(struct ndpi_ipv6hdr));
    l4len = ntohs(iph_v6->payload_len);
    l4protocol = iph_v6->nexthdr;

    // we need to handle IPv6 extension headers if present
    if(ndpi_handle_ipv6_extension_headers(ndpi_struct, &l4ptr, &l4len, &l4protocol) != 0) {
      return 1;
    }

  }
#endif
  else {
    return 1;
  }

  if(l4_return != NULL) {
    *l4_return = l4ptr;
  }

  if(l4_len_return != NULL) {
    *l4_len_return = l4len;
  }

  if(l4_protocol_return != NULL) {
    *l4_protocol_return = l4protocol;
  }

  return 0;
}

static int ndpi_init_packet_header(struct ndpi_detection_module_struct *ndpi_struct,
				   struct ndpi_flow_struct *flow,
				   unsigned short packetlen)
{
  const struct ndpi_iphdr *decaps_iph = NULL;
  u_int16_t l3len;
  u_int16_t l4len;
  const u_int8_t *l4ptr;
  u_int8_t l4protocol;
  u_int8_t l4_result;

  /* reset payload_packet_len, will be set if ipv4 tcp or udp */
  flow->packet.payload_packet_len = 0;
  flow->packet.l4_packet_len = 0;
  flow->packet.l3_packet_len = packetlen;

  flow->packet.tcp = NULL;
  flow->packet.udp = NULL;
  flow->packet.generic_l4_ptr = NULL;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  flow->packet.iphv6 = NULL;
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

  l3len =flow->packet.l3_packet_len;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(flow->packet.iph != NULL) {
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

    decaps_iph =flow->packet.iph;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
  }
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

  if(decaps_iph->version == 4 && decaps_iph->ihl >= 5) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "ipv4 header\n");
  }
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  else if(decaps_iph->version == 6 && l3len >= sizeof(struct ndpi_ipv6hdr) &&
	  (ndpi_struct->ip_version_limit & NDPI_DETECTION_ONLY_IPV4) == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "ipv6 header\n");
    flow->packet.iphv6 = (struct ndpi_ipv6hdr *)flow->packet.iph;
    flow->packet.iph = NULL;
  }
#endif
  else {
    flow->packet.iph = NULL;
    return 1;
  }


  /* needed:
   *  - unfragmented packets
   *  - ip header <= packet len
   *  - ip total length >= packet len
   */


  l4ptr = NULL;
  l4len = 0;
  l4protocol = 0;

  l4_result = ndpi_detection_get_l4_internal(ndpi_struct, (const u_int8_t *) decaps_iph, l3len, &l4ptr, &l4len, &l4protocol, 0);

  if(l4_result != 0) {
    return 1;
  }

  flow->packet.l4_protocol = l4protocol;
  flow->packet.l4_packet_len = l4len;

  /* tcp / udp detection */
  if(l4protocol == 6  &&flow->packet.l4_packet_len >= 20 /* min size of tcp */ ) {
    /* tcp */
    flow->packet.tcp = (struct ndpi_tcphdr *) l4ptr;

    if(flow->packet.l4_packet_len >=flow->packet.tcp->doff * 4) {
      flow->packet.payload_packet_len =
	flow->packet.l4_packet_len -flow->packet.tcp->doff * 4;
      flow->packet.actual_payload_len =flow->packet.payload_packet_len;
      flow->packet.payload = ((u_int8_t *)flow->packet.tcp) + (flow->packet.tcp->doff * 4);

      /* check for new tcp syn packets, here
       * idea: reset detection state if a connection is unknown
       */
      if (flow && flow->packet.tcp->syn != 0
	 && flow->packet.tcp->ack == 0
	 && flow->init_finished != 0
	 && ((flow->ndpi_result_ip == NDPI_RESULT_IP_STILL_UNKNOWN) || (flow->ndpi_result_ip == NDPI_RESULT_IP_UNKNOWN))
	 && ((flow->ndpi_result_base == NDPI_RESULT_BASE_STILL_UNKNOWN) || (flow->ndpi_result_base == NDPI_RESULT_BASE_UNKNOWN))
	 && ((flow->ndpi_result_app == NDPI_RESULT_APP_STILL_UNKNOWN) || (flow->ndpi_result_app == NDPI_RESULT_APP_STILL_UNKNOWN))
	 && ((flow->ndpi_result_content == NDPI_RESULT_CONTENT_STILL_UNKNOWN) || (flow->ndpi_result_content == NDPI_RESULT_CONTENT_UNKNOWN))
	 && ((flow->ndpi_result_service == NDPI_RESULT_SERVICE_STILL_UNKNOWN) || (flow->ndpi_result_service == NDPI_RESULT_SERVICE_UNKNOWN))
	 && ((flow->ndpi_result_cdn == NDPI_RESULT_CDN_STILL_UNKNOWN) || (flow->ndpi_result_cdn == NDPI_RESULT_CDN_UNKNOWN))) {

	memset(flow, 0, sizeof(*(flow)));

	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "%s:%u: tcp syn packet for unknown protocol, reset detection state\n", __FUNCTION__, __LINE__);

      }
    } else {
      /* tcp header not complete */
      flow->packet.tcp = NULL;
    }
  } else if(l4protocol == 17 /* udp */  &&flow->packet.l4_packet_len >= 8 /* size of udp */ ) {
    flow->packet.udp = (struct ndpi_udphdr *) l4ptr;
    flow->packet.payload_packet_len =flow->packet.l4_packet_len - 8;
    flow->packet.payload = ((u_int8_t *)flow->packet.udp) + 8;
  } else {
    flow->packet.generic_l4_ptr = l4ptr;
  }
  return 0;
}


#if !defined(WIN32)
static inline
#else
__forceinline static
#endif
void ndpi_connection_tracking(struct ndpi_detection_module_struct *ndpi_struct,
			      struct ndpi_flow_struct *flow)
{
  /* const for gcc code optimisation and cleaner code */
  struct ndpi_packet_struct *packet = &flow->packet;
  const struct ndpi_iphdr *iph = packet->iph;
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  const struct ndpi_ipv6hdr *iphv6 = packet->iphv6;
#endif
  const struct ndpi_tcphdr *tcph = packet->tcp;

  u_int8_t proxy_enabled = 0;
  packet->tcp_retransmission = 0;
  packet->packet_direction = 0;


  if(iph != NULL && iph->saddr < iph->daddr)
    packet->packet_direction = 1;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(iphv6 != NULL && NDPI_COMPARE_IPV6_ADDRESS_STRUCTS(&iphv6->saddr, &iphv6->daddr) != 0)
    packet->packet_direction = 1;
#endif

  packet->packet_lines_parsed_complete = 0;
  packet->packet_unix_lines_parsed_complete = 0;
  if(flow == NULL)
    return;

  if(flow->init_finished == 0) {
    flow->init_finished = 1;
    flow->setup_packet_direction = packet->packet_direction;
  }

  if(tcph != NULL) {
    /* reset retried bytes here before setting it */
    packet->num_retried_bytes = 0;
    
    packet->packet_direction = (tcph->source < tcph->dest) ? 1 : 0;

    if(tcph->syn != 0 && tcph->ack == 0 && flow->l4.tcp.seen_syn == 0 && flow->l4.tcp.seen_syn_ack == 0
       && flow->l4.tcp.seen_ack == 0) {
      flow->l4.tcp.seen_syn = 1;
    }
    if(tcph->syn != 0 && tcph->ack != 0 && flow->l4.tcp.seen_syn == 1 && flow->l4.tcp.seen_syn_ack == 0
       && flow->l4.tcp.seen_ack == 0) {
      flow->l4.tcp.seen_syn_ack = 1;
    }
    if(tcph->syn == 0 && tcph->ack == 1 && flow->l4.tcp.seen_syn == 1 && flow->l4.tcp.seen_syn_ack == 1
       && flow->l4.tcp.seen_ack == 0) {
      flow->l4.tcp.seen_ack = 1;
    }
    if((flow->next_tcp_seq_nr[0] == 0 && flow->next_tcp_seq_nr[1] == 0)
       || (proxy_enabled && (flow->next_tcp_seq_nr[0] == 0 || flow->next_tcp_seq_nr[1] == 0))) {
      
      /* initalize tcp sequence counters */
      /* the ack flag needs to be set to get valid sequence numbers from the other
       * direction. Usually it will catch the second packet syn+ack but it works
       * also for asymmetric traffic where it will use the first data packet
       *
       * if the syn flag is set add one to the sequence number,
       * otherwise use the payload length.
       */
      if(tcph->ack != 0) {
	flow->next_tcp_seq_nr[flow->packet.packet_direction] =
	  ntohl(tcph->seq) + (tcph->syn ? 1 : packet->payload_packet_len);
	if(!proxy_enabled) {
	  flow->next_tcp_seq_nr[1 -flow->packet.packet_direction] = ntohl(tcph->ack_seq);
	}
      }
    } else if(packet->payload_packet_len > 0) {
      /* check tcp sequence counters */
      if(((u_int32_t)
	  (ntohl(tcph->seq) -
	   flow->next_tcp_seq_nr[packet->packet_direction])) >
	 ndpi_struct->tcp_max_retransmission_window_size) {

	packet->tcp_retransmission = 1;


	/*CHECK IF PARTIAL RETRY IS HAPPENENING */
	if((flow->next_tcp_seq_nr[packet->packet_direction] - ntohl(tcph->seq) < packet->payload_packet_len)) {
	  /* num_retried_bytes actual_payload_len hold info about the partial retry
	     analyzer which require this info can make use of this info
	     Other analyzer can use packet->payload_packet_len */
	  packet->num_retried_bytes = (u_int16_t)(flow->next_tcp_seq_nr[packet->packet_direction] - ntohl(tcph->seq));
	  packet->actual_payload_len = packet->payload_packet_len - packet->num_retried_bytes;
	  flow->next_tcp_seq_nr[packet->packet_direction] = ntohl(tcph->seq) + packet->payload_packet_len;
	}
      }
      /*normal path
	actual_payload_len is initialized to payload_packet_len during tcp header parsing itself.
	It will be changed only in case of retransmission */
      else {
	packet->num_retried_bytes = 0;
	flow->next_tcp_seq_nr[packet->packet_direction] = ntohl(tcph->seq) + packet->payload_packet_len;
      }


    }

    if(tcph->rst) {
      flow->next_tcp_seq_nr[0] = 0;
      flow->next_tcp_seq_nr[1] = 0;
    }
  } //else if(udph != NULL) {
    // packet->packet_direction = (tcph->source < tcph->dest) ? 1 : 0;
  //}

  if(flow->packet_counter < MAX_PACKET_COUNTER && packet->payload_packet_len) {
    flow->packet_counter++;
  }

  if(flow->packet_direction_counter[packet->packet_direction] < MAX_PACKET_COUNTER && packet->payload_packet_len) {
    flow->packet_direction_counter[packet->packet_direction]++;
  }

  if(flow->byte_counter[packet->packet_direction] + packet->payload_packet_len >
     flow->byte_counter[packet->packet_direction]) {
    flow->byte_counter[packet->packet_direction] += packet->payload_packet_len;
  }
}

void ndpi_detect_level_base(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  
  int i, j, k;
  int privileged_position, normal_position;
  int matched_port;
  
  /* Sort the scanners - at first, place the scanners, which fit the port numbers from the packet. */
  
  int privileged_list[NDPI_RESULT_BASE_LAST];
  memset(privileged_list, 0, sizeof(int) * NDPI_RESULT_BASE_LAST);
  
  int normal_list[NDPI_RESULT_BASE_LAST];
  memset(normal_list, 0, sizeof(int) * NDPI_RESULT_BASE_LAST);
  
  privileged_position = 0;
  normal_position = 0;
  
  for (i = 0; i < NDPI_RESULT_BASE_LAST; i++) {
    
    /* Omit this scanner if it is already excluded. */
    if (flow->ndpi_excluded_base[i] != 0) {
      continue;
    }
    
    /* Omit and exclude the scanner if there is no scan function. */
    if (ndpi_struct->ndpi_scanners_base[i].func == NULL) {
      flow->ndpi_excluded_base[i] = 1;
      continue;
    }
    
    /* Omit the scanner if the bitmask does not comply to the one from the packet.
     */
    
    if (((flow->packet.ndpi_selection_packet) & (ndpi_struct->ndpi_scanners_base[i].ndpi_selection_packet)) != ndpi_struct->ndpi_scanners_base[i].ndpi_selection_packet) {
      continue;
    }
    
    /* Check if the scanner contains a matching port or not. */
    matched_port = 0;
    
    for (j = 0; j < 5; j++) {
      if (flow->ndpi_result_ip == NDPI_RESULT_IP_TCP) {
	if (ndpi_struct->ndpi_scanners_base[i].default_tcp_ports[j] != 0) {
	  if (ndpi_struct->ndpi_scanners_base[i].default_tcp_ports[j] == ntohs(flow->packet.tcp->dest)) {
	    matched_port = 1;
	    break;
	  }
	  
	  if (ndpi_struct->ndpi_scanners_base[i].default_tcp_ports[j] == ntohs(flow->packet.tcp->source)) {
	    matched_port = 1;
	    break;
	  }
	}
      } else {
	if (ndpi_struct->ndpi_scanners_base[i].default_udp_ports[j] != 0) {
	  if (ndpi_struct->ndpi_scanners_base[i].default_udp_ports[j] == ntohs(flow->packet.udp->dest)) {
	    matched_port = 1;
	    break;
	  }
	  
	  if (ndpi_struct->ndpi_scanners_base[i].default_udp_ports[j] == ntohs(flow->packet.udp->source)) {
	    matched_port = 1;
	    break;
	  }	
	}
      }
    }
    
    if (matched_port == 1) {
      privileged_list[privileged_position] = i;
      privileged_position++;
    } else {
      normal_list[normal_position] = i;
      normal_position++;
    }
    
  }
  
  /* For each of the available scanners - privileged list. */
  for (i = 0; i < NDPI_RESULT_BASE_LAST; i++) {
    
    /* Break after the list is done. */
    if (privileged_list[i] == 0) {
      break;
    }
    
    /* Run the scanner. */
    (*ndpi_struct->ndpi_scanners_base[privileged_list[i]].func)(ndpi_struct, flow);
    
    /* Exclude all the other scanners if the match was found. */
    if (flow->ndpi_result_base != NDPI_RESULT_BASE_STILL_UNKNOWN) {
      for (k = 0; k < NDPI_RESULT_BASE_LAST; k++) {
	if (k != privileged_list[i]) {
	  flow->ndpi_excluded_base[k] = 1;
	}
      }
    }
    
  }
  
  /* For each of the available scanners - normal list. */
  for (i = 0; i < NDPI_RESULT_BASE_LAST; i++) {
    
    /* Break after the list is done. */
    if (normal_list[i] == 0) {
      break;
    }
    
    /* Run the scanner. */
    (*ndpi_struct->ndpi_scanners_base[normal_list[i]].func)(ndpi_struct, flow);
    
    /* Exclude all the other scanners if the match was found. */
    if (flow->ndpi_result_base != NDPI_RESULT_BASE_STILL_UNKNOWN) {
      for (k = 0; k < NDPI_RESULT_BASE_LAST; k++) {
	if (k != normal_list[i]) {
	  flow->ndpi_excluded_base[k] = 1;
	}
      }
    }    
    
  }  
  
}

void ndpi_detect_level_app(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  
  int i, j, k;
  int privileged_position, normal_position;
  int matched_port;
  
  /* Sort the scanners - at first, place the scanners, which fit the port numbers from the packet. */
  
  int privileged_list[NDPI_RESULT_APP_LAST];
  memset(privileged_list, 0, sizeof(int) * NDPI_RESULT_APP_LAST);
  
  int normal_list[NDPI_RESULT_APP_LAST];
  memset(normal_list, 0, sizeof(int) * NDPI_RESULT_APP_LAST);
  
  privileged_position = 0;
  normal_position = 0;
  
  for (i = 0; i < NDPI_RESULT_APP_LAST; i++) {
    
    /* Omit this scanner if it is already excluded. */
    if (flow->ndpi_excluded_app[i] != 0) {
      continue;
    }
    
    /* Omit and exclude the scanner if there is no scan function. */
    if (ndpi_struct->ndpi_scanners_app[i].func == NULL) {
      flow->ndpi_excluded_app[i] = 1;
      continue;
    }
    
    /* Omit the scanner if the bitmask does not comply to the one from the packet.
     */
    
    if (((flow->packet.ndpi_selection_packet) & (ndpi_struct->ndpi_scanners_app[i].ndpi_selection_packet)) != ndpi_struct->ndpi_scanners_app[i].ndpi_selection_packet) {
      continue;
    }
    
    /* Check if the scanner contains a matching port or not. */
    matched_port = 0;
    
    for (j = 0; j < 5; j++) {
      if (flow->ndpi_result_ip == NDPI_RESULT_IP_TCP) {
	if (ndpi_struct->ndpi_scanners_app[i].default_tcp_ports[j] != 0) {
	  if (ndpi_struct->ndpi_scanners_app[i].default_tcp_ports[j] == ntohs(flow->packet.tcp->dest)) {
	    matched_port = 1;
	    break;
	  }
	  
	  if (ndpi_struct->ndpi_scanners_app[i].default_tcp_ports[j] == ntohs(flow->packet.tcp->source)) {
	    matched_port = 1;
	    break;
	  }
	}
      } else {
	if (ndpi_struct->ndpi_scanners_app[i].default_udp_ports[j] != 0) {
	  if (ndpi_struct->ndpi_scanners_app[i].default_udp_ports[j] == ntohs(flow->packet.udp->dest)) {
	    matched_port = 1;
	    break;
	  }
	  
	  if (ndpi_struct->ndpi_scanners_app[i].default_udp_ports[j] == ntohs(flow->packet.udp->source)) {
	    matched_port = 1;
	    break;
	  }	
	}
      }
    }
    
    if (matched_port == 1) {
      privileged_list[privileged_position] = i;
      privileged_position++;
    } else {
      normal_list[normal_position] = i;
      normal_position++;
    }
    
  }
  
  /* For each of the available scanners - privileged list. */
  for (i = 0; i < NDPI_RESULT_APP_LAST; i++) {
    
    /* Break after the list is done. */
    if (privileged_list[i] == 0) {
      break;
    }
    
    /* Run the scanner. */
    (*ndpi_struct->ndpi_scanners_app[privileged_list[i]].func)(ndpi_struct, flow);
    
     /* Exclude all the other scanners if the match was found. */
    if (flow->ndpi_result_app != NDPI_RESULT_APP_STILL_UNKNOWN) {
      for (k = 0; k < NDPI_RESULT_APP_LAST; k++) {
	if (k != privileged_list[i]) {
	  flow->ndpi_excluded_app[k] = 1;
	}
      }
    }
    
  }
  
  /* For each of the available scanners - normal list. */
  for (i = 0; i < NDPI_RESULT_APP_LAST; i++) {
    
    /* Break after the list is done. */
    if (normal_list[i] == 0) {
      break;
    }
    
    /* Run the scanner. */
    (*ndpi_struct->ndpi_scanners_app[normal_list[i]].func)(ndpi_struct, flow);
    
     /* Exclude all the other scanners if the match was found. */
    if (flow->ndpi_result_app != NDPI_RESULT_APP_STILL_UNKNOWN) {
      for (k = 0; k < NDPI_RESULT_APP_LAST; k++) {
	if (k != normal_list[i]) {
	  flow->ndpi_excluded_app[k] = 1;
	}
      }
    }    
    
  }  
  
}

void ndpi_process_ip_packet(struct ndpi_detection_module_struct *ndpi_struct,
					   struct ndpi_flow_struct *flow,
					   const unsigned char *packet,
					   const unsigned short packetlen,
					   const u_int32_t current_tick,
					   struct ndpi_id_struct *src,
					   struct ndpi_id_struct *dst
					  )
{
  
  int i, all_excluded;
  NDPI_SELECTION_BITMASK_PROTOCOL_SIZE ndpi_selection_packet;

  if (flow == NULL)
    return;

  /* Stop if everything is already detected. */
  if ((flow->ndpi_result_ip != NDPI_RESULT_IP_STILL_UNKNOWN) &&
    (flow->ndpi_result_base != NDPI_RESULT_BASE_STILL_UNKNOWN) &&
    (flow->ndpi_result_app != NDPI_RESULT_APP_STILL_UNKNOWN) &&
    (flow->ndpi_result_content != NDPI_RESULT_CONTENT_STILL_UNKNOWN) &&
    (flow->ndpi_result_service != NDPI_RESULT_SERVICE_STILL_UNKNOWN) &&
    (flow->ndpi_result_cdn != NDPI_RESULT_CDN_STILL_UNKNOWN)) {
    
    return;
  }

  /* We need at least 20 bytes for the IP header. */
  if (packetlen < 20) {
    return;
  }
  
  /* Clear the packet strcucture. */
  memset(&(flow->packet), 0, sizeof(struct ndpi_packet_struct));

  flow->packet.tick_timestamp = current_tick;

  /* Parse the packet. */
  flow->packet.iph = (struct ndpi_iphdr *) packet;
  
  if (ndpi_init_packet_header(ndpi_struct, flow, packetlen) != 0)
    return;

  flow->src = src, flow->dst = dst;

  ndpi_connection_tracking(ndpi_struct, flow);

  if (flow == NULL && (flow->packet.tcp != NULL || flow->packet.udp != NULL)) {
    return;
  }

  /* Build ndpi_selction packet bitmask */
  ndpi_selection_packet = 0;
  
  if (flow->packet.iph != NULL) {
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_IP | NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;
  }
  
  if (flow->packet.tcp != NULL) {
    ndpi_selection_packet |=
      (NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);
  }
  
  if (flow->packet.udp != NULL) {
    ndpi_selection_packet |=
      (NDPI_SELECTION_BITMASK_PROTOCOL_INT_UDP | NDPI_SELECTION_BITMASK_PROTOCOL_INT_TCP_OR_UDP);
  }
  
  if (flow->packet.payload_packet_len != 0) {
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_HAS_PAYLOAD;
  }

  if (flow->packet.tcp_retransmission == 0) {
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_NO_TCP_RETRANSMISSION;
  }
  
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(flow->packet.iphv6 != NULL) {
    ndpi_selection_packet |= NDPI_SELECTION_BITMASK_PROTOCOL_IPV6 | NDPI_SELECTION_BITMASK_PROTOCOL_IPV4_OR_IPV6;
  }
#endif							/* NDPI_DETECTION_SUPPORT_IPV6 */

  flow->packet.ndpi_selection_packet = ndpi_selection_packet;

  /* Find the IP protocol level. */
  if (flow->ndpi_result_ip == NDPI_RESULT_IP_STILL_UNKNOWN) {
    
    for (i = 0; i < NDPI_RESULT_IP_LAST; i++) {
      if (ndpi_struct->ndpi_scanners_ip[i].func != NULL) {
	(*ndpi_struct->ndpi_scanners_ip[i].func)(ndpi_struct, flow);
      }
      
      if (flow->ndpi_result_ip != NDPI_RESULT_IP_STILL_UNKNOWN) {
	break;
      }
    }
  }
  
  /* The rest of the function should be done only for TCP or UDP. */
  if ((flow->ndpi_result_ip != NDPI_RESULT_IP_TCP) && (flow->ndpi_result_ip != NDPI_RESULT_IP_UDP)) {
    flow->ndpi_result_base = NDPI_RESULT_BASE_UNKNOWN;
    flow->ndpi_result_app = NDPI_RESULT_APP_UNKNOWN;
    flow->ndpi_result_content = NDPI_RESULT_CONTENT_UNKNOWN;
    flow->ndpi_result_service = NDPI_RESULT_SERVICE_UNKNOWN;
    flow->ndpi_result_cdn = NDPI_RESULT_CDN_UNKNOWN;
    
    return;
  }
  
  /* The BASE level. */
  
  flow->ndpi_excluded_base[NDPI_RESULT_BASE_STILL_UNKNOWN] = 1;
  flow->ndpi_excluded_base[NDPI_RESULT_BASE_UNKNOWN] = 1;
  
  /* Assume that all the possible scanners were excluded. */
  all_excluded = 1;
  
  for (i = 0; i < NDPI_RESULT_BASE_LAST; i++) {
    if (flow->ndpi_excluded_base[i] == 0) {
      all_excluded = 0;
      break;
    }
  }  
  
  /* Run the scanners, which are not excluded. If all scanners excluded and no result found, mark that explicitly. */
  if (all_excluded == 0) {
    ndpi_detect_level_base(ndpi_struct, flow);
  } else {
    if (flow->ndpi_result_base == NDPI_RESULT_BASE_STILL_UNKNOWN) {
      flow->ndpi_result_base == NDPI_RESULT_BASE_UNKNOWN;
    }
  }
  
  /* The APPLICATION level. */
  
  flow->ndpi_excluded_app[NDPI_RESULT_APP_STILL_UNKNOWN] = 1;
  flow->ndpi_excluded_app[NDPI_RESULT_APP_UNKNOWN] = 1;
  
  /* Assume that all the possible scanners were excluded. */
  all_excluded = 1;
  
  for (i = 0; i < NDPI_RESULT_APP_LAST; i++) {
    if (flow->ndpi_excluded_app[i] == 0) {
      all_excluded = 0;
      break;
    }
  }  
  
  /* Run the scanners, which are not excluded. If all scanners excluded and no result found, mark that explicitly. */
  if (all_excluded == 0) {
    ndpi_detect_level_app(ndpi_struct, flow);
  } else {
    if (flow->ndpi_result_app == NDPI_RESULT_APP_STILL_UNKNOWN) {
      flow->ndpi_result_app == NDPI_RESULT_APP_UNKNOWN;
    }
  }  
  
  /* Now try to find the content. */
  
  if ((flow->ndpi_result_content == NDPI_RESULT_CONTENT_STILL_UNKNOWN) && (flow->packet_counter > 20)) {
    flow->ndpi_result_content = NDPI_RESULT_CONTENT_UNKNOWN;
  }
  
  if (flow->ndpi_result_content == NDPI_RESULT_CONTENT_STILL_UNKNOWN) {
    
    for (i = 0; i < NDPI_RESULT_CONTENT_LAST; i++) {
      if (ndpi_struct->ndpi_scanners_content[i].func != NULL) {
	(*ndpi_struct->ndpi_scanners_content[i].func)(ndpi_struct, flow);
      }
      
      if (flow->ndpi_result_content != NDPI_RESULT_CONTENT_STILL_UNKNOWN) {
	break;
      }
    }
  }
  
  /* Now try to find the service. */
  
  if ((flow->ndpi_result_service == NDPI_RESULT_SERVICE_STILL_UNKNOWN) && (flow->packet_counter > 20)) {
    flow->ndpi_result_service = NDPI_RESULT_SERVICE_UNKNOWN;
  }
  
  if (flow->ndpi_excluded_service == 0) {
    
    for (i = 0; i < NDPI_RESULT_SERVICE_LAST; i++) {
      if (ndpi_struct->ndpi_scanners_service[i].func != NULL) {
	(*ndpi_struct->ndpi_scanners_service[i].func)(ndpi_struct, flow);
      }
      
      if (flow->ndpi_excluded_service == 1) {
	break;
      }
    }
  }
  
    /* Now try to find the content delivery network. */
  
  if ((flow->ndpi_result_cdn == NDPI_RESULT_CDN_STILL_UNKNOWN) && (flow->packet_counter > 20)) {
    flow->ndpi_result_cdn = NDPI_RESULT_CDN_UNKNOWN;
  }
  
  if (flow->ndpi_excluded_cdn == 0) {
    
    for (i = 0; i < NDPI_RESULT_CDN_LAST; i++) {
      if (ndpi_struct->ndpi_scanners_cdn[i].func != NULL) {
	(*ndpi_struct->ndpi_scanners_cdn[i].func)(ndpi_struct, flow);
      }
      
      if (flow->ndpi_excluded_cdn == 1) {
	break;
      }
    }
  }
  
}

/* internal function for every detection to parse one packet and to increase the info buffer */
void ndpi_parse_packet_line_info(struct ndpi_detection_module_struct *ndpi_struct,
				 struct ndpi_flow_struct *flow)
{
  u_int32_t a;
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t end = packet->payload_packet_len - 1;
  if(packet->packet_lines_parsed_complete != 0)
    return;

  packet->packet_lines_parsed_complete = 1;
  packet->parsed_lines = 0;

  packet->empty_line_position_set = 0;

  packet->host_line.ptr = NULL;
  packet->host_line.len = 0;
  packet->referer_line.ptr = NULL;
  packet->referer_line.len = 0;
  packet->content_line.ptr = NULL;
  packet->content_line.len = 0;
  packet->accept_line.ptr = NULL;
  packet->accept_line.len = 0;
  packet->user_agent_line.ptr = NULL;
  packet->user_agent_line.len = 0;
  packet->http_url_name.ptr = NULL;
  packet->http_url_name.len = 0;
  packet->http_encoding.ptr = NULL;
  packet->http_encoding.len = 0;
  packet->http_transfer_encoding.ptr = NULL;
  packet->http_transfer_encoding.len = 0;
  packet->http_contentlen.ptr = NULL;
  packet->http_contentlen.len = 0;
  packet->http_cookie.ptr = NULL;
  packet->http_cookie.len = 0;
  packet->http_x_session_type.ptr = NULL;
  packet->http_x_session_type.len = 0;
  packet->server_line.ptr = NULL;
  packet->server_line.len = 0;
  packet->http_method.ptr = NULL;
  packet->http_method.len = 0;
  packet->http_response.ptr = NULL;
  packet->http_response.len = 0;

  if((packet->payload_packet_len == 0)
     || (packet->payload == NULL))
    return;

  packet->line[packet->parsed_lines].ptr = packet->payload;
  packet->line[packet->parsed_lines].len = 0;

  for (a = 0; a < end; a++) {
    if(get_u_int16_t(packet->payload, a) == ntohs(0x0d0a)) {
      packet->line[packet->parsed_lines].len = (u_int16_t)(((unsigned long) &packet->payload[a]) - ((unsigned long) packet->line[packet->parsed_lines].ptr));

      if(packet->parsed_lines == 0 && packet->line[0].len >= NDPI_STATICSTRING_LEN("HTTP/1.1 200 ") &&
	 memcmp(packet->line[0].ptr, "HTTP/1.", NDPI_STATICSTRING_LEN("HTTP/1.")) == 0 &&
	 packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] > '0' &&
	 packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.1 ")] < '6') {
	packet->http_response.ptr = &packet->line[0].ptr[NDPI_STATICSTRING_LEN("HTTP/1.1 ")];
	packet->http_response.len = packet->line[0].len - NDPI_STATICSTRING_LEN("HTTP/1.1 ");
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
		 "ndpi_parse_packet_line_info: HTTP response parsed: \"%.*s\"\n",
		 packet->http_response.len, packet->http_response.ptr);
      }
      if(packet->line[packet->parsed_lines].len > NDPI_STATICSTRING_LEN("Server:") + 1
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Server:", NDPI_STATICSTRING_LEN("Server:")) == 0) {
	// some stupid clients omit a space and place the servername directly after the colon
	if(packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:")] == ' ') {
	  packet->server_line.ptr =
	    &packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:") + 1];
	  packet->server_line.len =
	    packet->line[packet->parsed_lines].len - (NDPI_STATICSTRING_LEN("Server:") + 1);
	} else {
	  packet->server_line.ptr = &packet->line[packet->parsed_lines].ptr[NDPI_STATICSTRING_LEN("Server:")];
	  packet->server_line.len = packet->line[packet->parsed_lines].len - NDPI_STATICSTRING_LEN("Server:");
	}
      }

      if(packet->line[packet->parsed_lines].len > 6
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Host:", 5) == 0) {
	// some stupid clients omit a space and place the hostname directly after the colon
	if(packet->line[packet->parsed_lines].ptr[5] == ' ') {
	  packet->host_line.ptr = &packet->line[packet->parsed_lines].ptr[6];
	  packet->host_line.len = packet->line[packet->parsed_lines].len - 6;
	} else {
	  packet->host_line.ptr = &packet->line[packet->parsed_lines].ptr[5];
	  packet->host_line.len = packet->line[packet->parsed_lines].len - 5;
	}
      }
      
      if(packet->line[packet->parsed_lines].len > 17
	 && memcmp(packet->line[packet->parsed_lines].ptr, "X-Forwarded-For:", 16) == 0) {
	// some stupid clients omit a space and place the hostname directly after the colon
	if(packet->line[packet->parsed_lines].ptr[16] == ' ') {
	  packet->forwarded_line.ptr = &packet->line[packet->parsed_lines].ptr[17];
	  packet->forwarded_line.len = packet->line[packet->parsed_lines].len - 17;
	} else {
	  packet->forwarded_line.ptr = &packet->line[packet->parsed_lines].ptr[16];
	  packet->forwarded_line.len = packet->line[packet->parsed_lines].len - 16;
	}
      }

      if(packet->line[packet->parsed_lines].len > 14
	 &&
	 (memcmp
	  (packet->line[packet->parsed_lines].ptr, "Content-Type: ",
	   14) == 0 || memcmp(packet->line[packet->parsed_lines].ptr, "Content-type: ", 14) == 0)) {
	packet->content_line.ptr = &packet->line[packet->parsed_lines].ptr[14];
	packet->content_line.len = packet->line[packet->parsed_lines].len - 14;
      }

      if(packet->line[packet->parsed_lines].len > 13
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Content-type:", 13) == 0) {
	packet->content_line.ptr = &packet->line[packet->parsed_lines].ptr[13];
	packet->content_line.len = packet->line[packet->parsed_lines].len - 13;
      }

      if(packet->line[packet->parsed_lines].len > 8
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Accept: ", 8) == 0) {
	packet->accept_line.ptr = &packet->line[packet->parsed_lines].ptr[8];
	packet->accept_line.len = packet->line[packet->parsed_lines].len - 8;
      }

      if(packet->line[packet->parsed_lines].len > 9
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Referer: ", 9) == 0) {
	packet->referer_line.ptr = &packet->line[packet->parsed_lines].ptr[9];
	packet->referer_line.len = packet->line[packet->parsed_lines].len - 9;
      }

      if(packet->line[packet->parsed_lines].len > 12
	 && (memcmp(packet->line[packet->parsed_lines].ptr, "User-Agent: ", 12) == 0 ||
	     memcmp(packet->line[packet->parsed_lines].ptr, "User-agent: ", 12) == 0)) {
	packet->user_agent_line.ptr = &packet->line[packet->parsed_lines].ptr[12];
	packet->user_agent_line.len = packet->line[packet->parsed_lines].len - 12;
      }

      if(packet->line[packet->parsed_lines].len > 18
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Content-Encoding: ", 18) == 0) {
	packet->http_encoding.ptr = &packet->line[packet->parsed_lines].ptr[18];
	packet->http_encoding.len = packet->line[packet->parsed_lines].len - 18;
      }

      if(packet->line[packet->parsed_lines].len > 19
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Transfer-Encoding: ", 19) == 0) {
	packet->http_transfer_encoding.ptr = &packet->line[packet->parsed_lines].ptr[19];
	packet->http_transfer_encoding.len = packet->line[packet->parsed_lines].len - 19;
      }
      if(packet->line[packet->parsed_lines].len > 16
	 && ((memcmp(packet->line[packet->parsed_lines].ptr, "Content-Length: ", 16) == 0)
	     || (memcmp(packet->line[packet->parsed_lines].ptr, "content-length: ", 16) == 0))) {
	packet->http_contentlen.ptr = &packet->line[packet->parsed_lines].ptr[16];
	packet->http_contentlen.len = packet->line[packet->parsed_lines].len - 16;
      }
      if(packet->line[packet->parsed_lines].len > 8
	 && memcmp(packet->line[packet->parsed_lines].ptr, "Cookie: ", 8) == 0) {
	packet->http_cookie.ptr = &packet->line[packet->parsed_lines].ptr[8];
	packet->http_cookie.len = packet->line[packet->parsed_lines].len - 8;
      }
      if(packet->line[packet->parsed_lines].len > 16
	 && memcmp(packet->line[packet->parsed_lines].ptr, "X-Session-Type: ", 16) == 0) {
	packet->http_x_session_type.ptr = &packet->line[packet->parsed_lines].ptr[16];
	packet->http_x_session_type.len = packet->line[packet->parsed_lines].len - 16;
      }


      if(packet->line[packet->parsed_lines].len == 0) {
	packet->empty_line_position = a;
	packet->empty_line_position_set = 1;
      }

      if(packet->parsed_lines >= (NDPI_MAX_PARSE_LINES_PER_PACKET - 1)) {
	return;
      }

      packet->parsed_lines++;
      packet->line[packet->parsed_lines].ptr = &packet->payload[a + 2];
      packet->line[packet->parsed_lines].len = 0;

      if((a + 2) >= packet->payload_packet_len) {

	return;
      }
      a++;
    }
  }

  if(packet->parsed_lines >= 1) {
    packet->line[packet->parsed_lines].len
      = (u_int16_t)(((unsigned long) &packet->payload[packet->payload_packet_len]) -
		    ((unsigned long) packet->line[packet->parsed_lines].ptr));
      
    packet->parsed_lines++;
  }
}

void ndpi_parse_packet_line_info_unix(struct ndpi_detection_module_struct *ndpi_struct,
				      struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t a;
  u_int16_t end = packet->payload_packet_len;
  if(packet->packet_unix_lines_parsed_complete != 0)
    return;



  packet->packet_unix_lines_parsed_complete = 1;
  packet->parsed_unix_lines = 0;

  if(packet->payload_packet_len == 0)
    return;

  packet->unix_line[packet->parsed_unix_lines].ptr = packet->payload;
  packet->unix_line[packet->parsed_unix_lines].len = 0;

  for (a = 0; a < end; a++) {
    if(packet->payload[a] == 0x0a) {
      packet->unix_line[packet->parsed_unix_lines].len = (u_int16_t)(
								     ((unsigned long) &packet->payload[a]) -
								     ((unsigned long) packet->unix_line[packet->parsed_unix_lines].ptr));

      if(packet->parsed_unix_lines >= (NDPI_MAX_PARSE_LINES_PER_PACKET - 1)) {
	break;
      }

      packet->parsed_unix_lines++;
      packet->unix_line[packet->parsed_unix_lines].ptr = &packet->payload[a + 1];
      packet->unix_line[packet->parsed_unix_lines].len = 0;

      if((a + 1) >= packet->payload_packet_len) {
	break;
      }
      
    }
  }
}

u_int16_t ndpi_check_for_email_address(struct ndpi_detection_module_struct *ndpi_struct,
				       struct ndpi_flow_struct *flow, u_int16_t counter)
{

  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "called ndpi_check_for_email_address\n");

  if(packet->payload_packet_len > counter && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
					      || (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z')
					      || (packet->payload[counter] >= '0' && packet->payload[counter] <= '9')
					      || packet->payload[counter] == '-' || packet->payload[counter] == '_')) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "first letter\n");
    counter++;
    while (packet->payload_packet_len > counter
	   && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
	       || (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z')
	       || (packet->payload[counter] >= '0' && packet->payload[counter] <= '9')
	       || packet->payload[counter] == '-' || packet->payload[counter] == '_'
	       || packet->payload[counter] == '.')) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "further letter\n");
      counter++;
      if(packet->payload_packet_len > counter && packet->payload[counter] == '@') {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "@\n");
	counter++;
	while (packet->payload_packet_len > counter
	       && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
		   || (packet->payload[counter] >= 'A' && packet->payload[counter] <= 'Z')
		   || (packet->payload[counter] >= '0' && packet->payload[counter] <= '9')
		   || packet->payload[counter] == '-' || packet->payload[counter] == '_')) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "letter\n");
	  counter++;
	  if(packet->payload_packet_len > counter && packet->payload[counter] == '.') {
	    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, ".\n");
	    counter++;
	    if(packet->payload_packet_len > counter + 1
	       && ((packet->payload[counter] >= 'a' && packet->payload[counter] <= 'z')
		   && (packet->payload[counter + 1] >= 'a' && packet->payload[counter + 1] <= 'z'))) {
	      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "two letters\n");
	      counter += 2;
	      if(packet->payload_packet_len > counter
		 && (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "whitespace1\n");
		return counter;
	      } else if(packet->payload_packet_len > counter && packet->payload[counter] >= 'a'
			&& packet->payload[counter] <= 'z') {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "one letter\n");
		counter++;
		if(packet->payload_packet_len > counter
		   && (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
		  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "whitespace2\n");
		  return counter;
		} else if(packet->payload_packet_len > counter && packet->payload[counter] >= 'a'
			  && packet->payload[counter] <= 'z') {
		  counter++;
		  if(packet->payload_packet_len > counter
		     && (packet->payload[counter] == ' ' || packet->payload[counter] == ';')) {
		    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "whitespace3\n");
		    return counter;
		  } else {
		    return 0;
		  }
		} else {
		  return 0;
		}
	      } else {
		return 0;
	      }
	    } else {
	      return 0;
	    }
	  }
	}
	return 0;
      }
    }
  }
  return 0;
}

u_int8_t ndpi_detection_get_l4(const u_int8_t * l3, u_int16_t l3_len, const u_int8_t ** l4_return, u_int16_t * l4_len_return,
			       u_int8_t * l4_protocol_return, u_int32_t flags) {
  return ndpi_detection_get_l4_internal(NULL, l3, l3_len, l4_return, l4_len_return, l4_protocol_return, flags);
}

/* check if the source ip address in packet and ip are equal */
/* NTOP */
int ndpi_packet_src_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t * ip)
{
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(packet->iphv6 != NULL) {
    if(packet->iphv6->saddr.ndpi_v6_u.u6_addr64[0] == ip->ipv6.ndpi_v6_u.u6_addr64[0] &&
       packet->iphv6->saddr.ndpi_v6_u.u6_addr64[1] == ip->ipv6.ndpi_v6_u.u6_addr64[1]) {

      return 1;
    } else {
      return 0;
    }
  }
#endif
  if(packet->iph->saddr == ip->ipv4) {
    return 1;
  }
  return 0;
}

/* check if the destination ip address in packet and ip are equal */
int ndpi_packet_dst_ip_eql(const struct ndpi_packet_struct *packet, const ndpi_ip_addr_t * ip)
{
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(packet->iphv6 != NULL) {
    if(packet->iphv6->daddr.ndpi_v6_u.u6_addr64[0] == ip->ipv6.ndpi_v6_u.u6_addr64[0] &&
       packet->iphv6->daddr.ndpi_v6_u.u6_addr64[1] == ip->ipv6.ndpi_v6_u.u6_addr64[1]) {
      return 1;
    } else {
      return 0;
    }
  }
#endif
  if(packet->iph->daddr == ip->ipv4) {
    return 1;
  }
  return 0;
}

void NDPI_PROTOCOL_IP_clear(ndpi_ip_addr_t * ip)
{
  memset(ip, 0, sizeof(ndpi_ip_addr_t));
}

/* get the source ip address from packet and put it into ip */
/* NTOP */
void ndpi_packet_src_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t * ip)
{
  NDPI_PROTOCOL_IP_clear(ip);
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(packet->iphv6 != NULL) {
    ip->ipv6.ndpi_v6_u.u6_addr64[0] = packet->iphv6->saddr.ndpi_v6_u.u6_addr64[0];
    ip->ipv6.ndpi_v6_u.u6_addr64[1] = packet->iphv6->saddr.ndpi_v6_u.u6_addr64[1];
  } else
#endif
    ip->ipv4 = packet->iph->saddr;
}

/* get the destination ip address from packet and put it into ip */
/* NTOP */
void ndpi_packet_dst_ip_get(const struct ndpi_packet_struct *packet, ndpi_ip_addr_t * ip)
{
  NDPI_PROTOCOL_IP_clear(ip);
#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(packet->iphv6 != NULL) {
    ip->ipv6.ndpi_v6_u.u6_addr64[0] = packet->iphv6->daddr.ndpi_v6_u.u6_addr64[0];
    ip->ipv6.ndpi_v6_u.u6_addr64[1] = packet->iphv6->daddr.ndpi_v6_u.u6_addr64[1];
  } else
#endif
    ip->ipv4 = packet->iph->daddr;
}

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
/* get the string representation of ip
 * returns a pointer to a static string
 * only valid until the next call of this function */
char *ndpi_get_ip_string(struct ndpi_detection_module_struct *ndpi_struct,
			 const ndpi_ip_addr_t * ip)
{
  const u_int8_t *a = (const u_int8_t *) &ip->ipv4;

#ifdef NDPI_DETECTION_SUPPORT_IPV6
  if(ip->ipv6.ndpi_v6_u.u6_addr32[1] != 0 || ip->ipv6.ndpi_v6_u.u6_addr64[1] != 0) {
    const u_int16_t *b = ip->ipv6.ndpi_v6_u.u6_addr16;
    snprintf(ndpi_struct->ip_string, NDPI_PROTOCOL_IP_STRING_SIZE, "%x:%x:%x:%x:%x:%x:%x:%x",
	     ntohs(b[0]), ntohs(b[1]), ntohs(b[2]), ntohs(b[3]),
	     ntohs(b[4]), ntohs(b[5]), ntohs(b[6]), ntohs(b[7]));
    return ndpi_struct->ip_string;
  }
#endif
  snprintf(ndpi_struct->ip_string, NDPI_PROTOCOL_IP_STRING_SIZE, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
  return ndpi_struct->ip_string;
}


/* get the string representation of the source ip address from packet */
char *ndpi_get_packet_src_ip_string(struct ndpi_detection_module_struct *ndpi_struct, const struct ndpi_packet_struct *packet)
{
  ndpi_ip_addr_t ip;
  ndpi_packet_src_ip_get(packet, &ip);
  return ndpi_get_ip_string(ndpi_struct, &ip);
}

/* get the string representation of the destination ip address from packet */
char *ndpi_get_packet_dst_ip_string(struct ndpi_detection_module_struct *ndpi_struct, const struct ndpi_packet_struct *packet)
{
  ndpi_ip_addr_t ip;
  ndpi_packet_dst_ip_get(packet, &ip);
  return ndpi_get_ip_string(ndpi_struct, &ip);
}
#endif							/* NDPI_ENABLE_DEBUG_MESSAGES */

/* ****************************************************** */

u_int16_t ntohs_ndpi_bytestream_to_number(const u_int8_t * str, u_int16_t max_chars_to_read, u_int16_t * bytes_read)
{
  u_int16_t val = ndpi_bytestream_to_number(str, max_chars_to_read, bytes_read);
  return ntohs(val);
}

/* ****************************************************** */
